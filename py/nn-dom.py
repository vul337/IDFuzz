# -*- coding: utf-8 -*-
'''
Workflow:
Read dom_bits_depth.txt, obtain the number of dom edges, and build NN.
Read seeds from queue/ and dominator coverage of each seed from cur_dom_bits/.
Vectorize seeds and start training NN.
After training, calculate gradients for all seeds and store them in memory, ready for communication with the fuzzer.
'''

import os, sys
import glob
import time
import random
import numpy as np
import torch
from torch import nn
from torch import optim
from torch.utils.data import TensorDataset, DataLoader
from sklearn.model_selection import train_test_split
import sysv_ipc as ipc
from pwn import info, success
# from tqdm import tqdm

# Choose a seed for random initialization
rand_seed = int(time.time())
np.random.seed(rand_seed)
random.seed(rand_seed)
torch.manual_seed(rand_seed)

# Get binary arguments
# python3 this.py target.bin out_dir(absolute path) key_id
argvv = sys.argv[1:]

BATCH_SIZE = 32
EPOCH = 5
HIDDEN_NEURON = 512

device = torch.device('cpu')
# device = torch.device('cuda:1')
# device = torch.device('cuda:2')

tmp_dir = os.getenv('TMP_DIR')

MAX_FILE_SIZE = 0
DOM_BB_NUM = None

all_dom_edge = [] # Edges to mutate, shape (n: n < 214,)
all_dom_target = [] # All targets corresponding to dom_edge
all_dom_depth = [] # Depths corresponding to dom_edge

bb_next_dom = {} # BB and the next domBB  
edge_to_bb = {} # Edge and the corresponding BB
bb_to_edges = {} # BB and corresponding edges (excluding dom edges)
seed_length = {} # Seed length
seed_bytes_to_mutate = {} # Seed mutation points

dombb_all = [] # Ordered domBB list
poor_seeds = [] # Seeds that do not cover any domBB

new_train = True # Whether a new training set was generated
train_last_time = 0 # Time of the last training set generation
last_query = "" # Last query

# Set up shared memory
info("Setting up shared memory")
try:
    shm_key = int(argvv[-1])
    info("Shared memory key %d", shm_key)
except:
    info("Shared memory key ID needs to be an integer!")
    exit()

shm = ipc.SharedMemory(shm_key, 0, 0)
shm.attach(0, 0)
success("Shared memory is ready")

'''
shm utils
'''
def shm_unlock():
    global shm
    shm.write("\x00") # 0 indicates shared memory is released and available for fuzzer to read/write

def shm_hold():
    global shm
    shm.write("\x02") # 2 indicates NN is training, fuzzer should not read/write

def myread():
    global shm
    while True:
        data = shm.read(1)
        if (data == b'\x01'): # 1 indicates shared memory has just been written by fuzzer, Python side can read/write
            break
    raw = shm.read(256)
    data_len = raw[1]
    data = raw[2:data_len+2]
    return data

def mywrite(input):
    global shm
    while True:
        data = shm.read(1)
        if (data == b'\x01'): # 1 indicates shared memory has just been written by fuzzer, Python side can read/write
            break
    shm.write(input, offset=2)
    shm.write(chr(len(input)), offset=1)
    shm.write("\x00")

def shm_detach():
    global shm
    shm.detach()

class TrainsetException(Exception):
    def __init__(self, message):
        super().__init__(message)

def trans_vec(bb_vec, dom_bits_levels): # compress dom vector
    return_vec = []
    index_to_trans = 0
    last_ele = 0
    for i in range(len(bb_vec)):
        if bb_vec[i] != 1.0:
            index_to_trans = i
            last_ele = bb_vec[i]
            break
    for i in range(len(dom_bits_levels) - 1, -1, -1):
        if index_to_trans != dom_bits_levels[i]:
            return_vec.append(1.0)
        else:
            return_vec.append(1.0)
            return_vec.append(last_ele)
            break
    while len(return_vec) < len(dom_bits_levels) + 1:
        return_vec.append(0.0)
    return return_vec

def trans_vec_index(index, dom_bits_levels): # map between original and compressed vector indices
    for i in range(len(dom_bits_levels)):
        if index >= dom_bits_levels[i]:
            return len(dom_bits_levels) - i
    return 0

# Process training data from AFL raw data
def init():
    # seed and its cur_dom_bits file names should be the same
    seed_dom_bits_filename1 = glob.glob(argvv[1] + '/cur_dom_bits/id*')
    seed_dom_bits_filename2 = glob.glob(argvv[1] + '/cur_dom_bits_backup/*')
    seed_dom_bits_filename = seed_dom_bits_filename1 + seed_dom_bits_filename2
    seed_dom_bits_filename_train = [] # train set

    all_dom_edge.clear()
    all_dom_depth.clear()
    all_dom_target.clear()
    bb_next_dom.clear()
    edge_to_bb.clear()
    bb_to_edges.clear()
    dombb_all.clear()

    # Read dom_bits_depth.txt and obtain the number of dom edges
    with open(tmp_dir + '/dom_bits_depth.txt', 'r') as f:
        for line in f:
            edge, edgeinfo = line.strip().split(':')
            depth, target, bb, next_bb = edgeinfo.split(',')
            all_dom_edge.append(int(edge))
            all_dom_depth.append(int(depth))
            all_dom_target.append(int(target))
            if int(bb) not in dombb_all:
                bb_next_dom[int(bb)] = int(next_bb)
                bb_to_edges[int(bb)] = []
                dombb_all.append(int(bb))
                if int(next_bb) == 0: # record non-dom edge
                    bb_to_edges[int(bb)].append(int(edge))
            else:
                if int(next_bb) != 0: # dom edge
                    bb_next_dom[int(bb)] = int(next_bb)
                else: # record non-dom edge
                    bb_to_edges[int(bb)].append(int(edge))
            edge_to_bb[int(edge)] = int(bb)

    # Read and process binary files seeds & cur_dom_bits
    print('Starting to read seeds & cur_dom_bits...')
    SEEDS_TRAIN = [] # Raw bytes of seeds used for training, shape (N, MAX_FILE_SIZE)
    FNAMES = [] # All seed file names
    DOM_BITS = [] # Dom edges covered by all seeds
    DOM_BITS_TRAIN = [] # Dom edges covered by seeds used for training
    
    global MAX_FILE_SIZE
    max_file_length = 0
    seed_to_dom_bits = {} # seed file name corresponding to dom-bits
    seed_to_dom_bits_level = {} # seed file name corresponding to dom-bits level
    dom_bits_levels = [] # all possible dom-bits levels
    max_bits_level = 0 # max dom-bits levels
    max_bits_level_branches = {} #

    for bits in seed_dom_bits_filename:
        filename = bits.split('/')[-1]
        the_path = ''
        if filename[0] == 'i':
            the_path = argvv[1] + '/queue/'
        else:
            the_path = argvv[1] + '/queue_backup/'
        with open(the_path + filename, 'r') as f:
            f_bytes = np.fromfile(f, dtype=np.uint8)
            if len(f_bytes) > max_file_length:
                max_file_length = len(f_bytes)
            seed_length[filename] = len(f_bytes)
        with open(bits, 'r') as f: 
            bbs = [] # all covered dom BB ids
            bb_vec = []
            dom_bits = np.fromfile(f, dtype=np.uint8) # shape (65536,)
            for edge in all_dom_edge:
                if dom_bits[edge]:
                    if edge_to_bb[edge] not in bbs:
                        bbs.append(edge_to_bb[edge])
            
            if len(bbs) == 0:
                if filename not in poor_seeds:
                    poor_seeds.append(filename)
                continue
            
            the_last_cover = -1 # ID of the last covered domBB
            cover_num = 0 # num of covered domBBs
            for ele in dombb_all:
                if ele in bbs:
                    bb_vec.append(1.0)
                    cover_num += 1
                    the_last_cover = ele
                else:
                    bb_vec.append(0.0)
            if bb_next_dom[the_last_cover] != 0 and dombb_all.index(the_last_cover) < len(dombb_all) - 1:
                branch = 0.0 # branching encoding
                for edge in all_dom_edge:
                    if edge_to_bb[edge] == the_last_cover and dom_bits[edge]:
                        if edge in bb_to_edges[the_last_cover]: # non-dom edge
                            branch += 1 << (bb_to_edges[the_last_cover].index(edge))
                        else:
                            branch = 0.0
                            break
                branch /= 1 << len(bb_to_edges[the_last_cover])
                bb_vec[dombb_all.index(the_last_cover) + 1] = branch
                cover_num += branch
            for idx in range(len(bb_vec) - 1, -1, -1):
                if bb_vec[idx] != 0:
                    for idx_ in range(idx):
                        if bb_vec[idx_] == 0:
                            cover_num += 1
                            bb_vec[idx_] = 1.0
                    break
            if int(cover_num) > max_bits_level:
                max_bits_level = int(cover_num)
                max_bits_level_branches = {}
                max_bits_level_branches[cover_num] = 1 # each cover_num represents a branching, record all branchings (if int(cover_num) == max_bits_level) and their corresponding sample counts
            elif int(cover_num) == max_bits_level:
                if cover_num in max_bits_level_branches.keys():
                    max_bits_level_branches[cover_num] += 1
                else:
                    max_bits_level_branches[cover_num] = 1
            if int(cover_num) not in dom_bits_levels:
                dom_bits_levels.append(int(cover_num))
            DOM_BITS.append(bb_vec)
            FNAMES.append(filename)
            seed_to_dom_bits_level[bits] = cover_num
            seed_to_dom_bits[filename] = bb_vec
    print('Number of samples covering the most dom BBs: ' + str(sum(max_bits_level_branches.values()))) # Number of samples covering the most dom BBs, an important criterion for determining if the training set is sufficient
    dom_bits_levels.sort(reverse=True)
    print('Dom bits levels: ' + str(dom_bits_levels))

    MAX_FILE_SIZE = min(max_file_length, 1024)
    print('Input size: ' + str(MAX_FILE_SIZE))

    trainset_balance = True
    need_second = True
    backup_seeds_list = [] # seeds used for sample generation in backup mode
    backup_bits_list = [] # edges that generated samples need to cover / must not cover

    seed_to_dom_bits_sorted_list = sorted(seed_to_dom_bits_level.items(), key=lambda x: x[1], reverse=True)

    if sum(max_bits_level_branches.values()) < 20: # Not enough samples with maximum dom BB coverage
        trainset_balance = False
        for i in range(len(seed_to_dom_bits_sorted_list)):
            if int(seed_to_dom_bits_sorted_list[i][1]) != max_bits_level:
                break
            seed_dom_bits_filename_train.append(seed_to_dom_bits_sorted_list[i][0]) # add to trainset
            backup_seed = seed_to_dom_bits_sorted_list[i][0].split('/')[-1]
            if backup_seed not in backup_seeds_list and backup_seed[0]=='i':
                backup_seeds_list.append(backup_seed) # add to backup seeds
        for edge in all_dom_edge:
            if edge_to_bb[edge] == dombb_all[max_bits_level-1] and str(edge) not in backup_bits_list:
                backup_bits_list.append(str(edge)) # add to backup edges
    
    elif sum(max_bits_level_branches.values()) > 200:
        if len(max_bits_level_branches) == 1: # Seeds covering the most dom BBs all have the same branching behavior
            for i in range(len(seed_to_dom_bits_sorted_list)):
                if int(seed_to_dom_bits_sorted_list[i][1]) != max_bits_level:
                    break
                seed_dom_bits_filename_train.append(seed_to_dom_bits_sorted_list[i][0])
                if len(seed_dom_bits_filename_train) == 200:
                    break
        else:
            need_second = False
            max_branch = -1 # Branching with the largest proportion of samples
            max_branch_num = 0
            for cover_num in max_bits_level_branches.keys():
                if max_bits_level_branches[cover_num] > max_branch_num:
                    max_branch_num = max_bits_level_branches[cover_num]
                    max_branch = cover_num
            if max_branch_num > sum(max_bits_level_branches.values()) - 20:
                need_second = True
                for i in range(len(seed_to_dom_bits_sorted_list)):
                    if int(seed_to_dom_bits_sorted_list[i][1]) != max_bits_level:
                        break
                    backup_seed = seed_to_dom_bits_sorted_list[i][0].split('/')[-1]
                    if seed_to_dom_bits_sorted_list[i][1] != max_branch and backup_seed not in backup_seeds_list and backup_seed[0] == 'i':
                        backup_seeds_list.append(backup_seed)
                for edge in all_dom_edge:
                    if edge_to_bb[edge] == dombb_all[max_bits_level-1] and str(edge) not in backup_bits_list:
                        backup_bits_list.append(str(edge))
            if max_branch_num < 180:
                for i in range(200):
                    seed_dom_bits_filename_train.append(seed_to_dom_bits_sorted_list[i][0])
            else:
                max_branch_num_in_trainset = 0
                for i in range(len(seed_to_dom_bits_sorted_list)):
                    if int(seed_to_dom_bits_sorted_list[i][1]) != max_bits_level:
                        break
                    if seed_to_dom_bits_sorted_list[i][1] != max_branch:
                        seed_dom_bits_filename_train.append(seed_to_dom_bits_sorted_list[i][0])
                    else:
                        if max_branch_num_in_trainset < 180:
                            seed_dom_bits_filename_train.append(seed_to_dom_bits_sorted_list[i][0])
                            max_branch_num_in_trainset += 1
                seed_dom_bits_filename_train = seed_dom_bits_filename_train[0:200]
    else:
        for i in range(len(seed_to_dom_bits_sorted_list)):
            if int(seed_to_dom_bits_sorted_list[i][1]) != max_bits_level:
                break
            seed_dom_bits_filename_train.append(seed_to_dom_bits_sorted_list[i][0])
            backup_seed = seed_to_dom_bits_sorted_list[i][0].split('/')[-1]
            if backup_seed not in backup_seeds_list and backup_seed[0]=='i':
                backup_seeds_list.append(backup_seed)
        for edge in all_dom_edge:
            if edge_to_bb[edge] == dombb_all[max_bits_level-1] and str(edge) not in backup_bits_list:
                backup_bits_list.append(str(edge))

    if len(dom_bits_levels) == 1:
        if need_second:
            trainset_balance = False
            if len(max_bits_level_branches.keys()) == 1:
                raise TrainsetException("'The trainset only has one label!'") 
    else:
        second_level_num = 0
        for i in range(len(seed_to_dom_bits_sorted_list)):
            if int(seed_to_dom_bits_sorted_list[i][1]) < dom_bits_levels[1]:
                break
            if int(seed_to_dom_bits_sorted_list[i][1]) == dom_bits_levels[1]:
                seed_dom_bits_filename_train.append(seed_to_dom_bits_sorted_list[i][0])
                second_level_num += 1
        if need_second and second_level_num < 20 and random.randint(0,9) > 0: # don't keep getting stuck here
            trainset_balance = False
            for i in range(len(seed_to_dom_bits_sorted_list)):
                if int(seed_to_dom_bits_sorted_list[i][1]) < dom_bits_levels[1]:
                    break
                backup_seed = seed_to_dom_bits_sorted_list[i][0].split('/')[-1]
                if int(seed_to_dom_bits_sorted_list[i][1]) == dom_bits_levels[1] and backup_seed not in backup_seeds_list and backup_seed[0]=='i':
                    backup_seeds_list.append(backup_seed)
            for edge in all_dom_edge:
                if edge_to_bb[edge] == dombb_all[dom_bits_levels[1]-1] and str(edge) not in backup_bits_list:
                    backup_bits_list.append(str(edge))
                if edge_to_bb[edge] == dombb_all[max_bits_level-1] and '-'+str(edge) not in backup_bits_list and str(edge) not in backup_bits_list:
                    backup_bits_list.append('-'+str(edge)) # do not cover max dom
    if trainset_balance:
        for i in range(len(seed_to_dom_bits_sorted_list)):
            if int(seed_to_dom_bits_sorted_list[i][1]) < dom_bits_levels[1]:
                seed_dom_bits_filename_train.append(seed_to_dom_bits_sorted_list[i][0])
    else:
        backup_seeds = open(tmp_dir + '/backup_seeds.txt', 'w')
        backup_bits = open(tmp_dir + '/backup_bits.txt', 'w')
        for seed in backup_seeds_list:
            backup_seeds.write(seed+'\n')
        for the_bits in backup_bits_list:
            backup_bits.write(the_bits+'\n')
        backup_seeds.close()
        backup_bits.close()

    seed_dom_bits_filename_train = seed_dom_bits_filename_train[:1000]
    
    trainset_distribution = {}
    for bits in seed_dom_bits_filename_train:
        filename = bits.split('/')[-1]
        if seed_to_dom_bits_level[bits] in trainset_distribution.keys():
            trainset_distribution[seed_to_dom_bits_level[bits]] += 1
        else:
            trainset_distribution[seed_to_dom_bits_level[bits]] = 1
        bb_vec = seed_to_dom_bits[filename]
        bb_vec_trans = trans_vec(bb_vec,dom_bits_levels)
        DOM_BITS_TRAIN.append(bb_vec_trans)
        the_path = ''
        if filename[0] == 'i':
            the_path = argvv[1]+'/queue/'
        else:
            the_path = argvv[1]+'/queue_backup/'
        with open(the_path + filename,'r') as f:
            f_bytes = np.fromfile(f, dtype=np.uint8)
            if len(f_bytes) > MAX_FILE_SIZE:
                SEEDS_TRAIN.append(f_bytes[:MAX_FILE_SIZE])
            else:
                f_bytes = np.pad(f_bytes,(0,MAX_FILE_SIZE - len(f_bytes)),'constant')
                SEEDS_TRAIN.append(f_bytes)
    
    print('trainset distribution: '+str(trainset_distribution))
    seeds = torch.as_tensor(SEEDS_TRAIN, dtype=torch.float32) / 255
    bitmaps = torch.as_tensor(DOM_BITS_TRAIN, dtype=torch.float32)
    print('finished reading seeds & cur_dom_bits.')
    trainset_levels = list(trainset_distribution.keys())
    trainset_levels.sort(reverse = True)

    return FNAMES, seeds, bitmaps, len(dom_bits_levels)+1, DOM_BITS, trainset_balance, dom_bits_levels, trainset_levels

"""
    FCN Model written in PyTorch
    input: seed file
    output: cur_dom_bits
"""

def accur_1(y_true, y_pred):
    y_true = torch.round(y_true)
    y_pred = torch.round(y_pred)
    wrong_num = torch.sub(float(DOM_BB_NUM),torch.sum(torch.eq(y_true,y_pred).float(),1))
    right_1_num = torch.sum(torch.logical_and(y_true.bool(),y_pred.bool()).float())
    acc = torch.mean(torch.div(right_1_num,wrong_num+right_1_num))
    return acc

# seed to dom_bits
class S2DModel(nn.Module):
    def __init__(self, num_classes, l2_reg=0.01):
        super(S2DModel, self).__init__()
        self.num_classes = num_classes
        self.l2_reg = l2_reg
        self.linear1 = nn.Linear(MAX_FILE_SIZE, HIDDEN_NEURON) # nn.Sequential(nn.Linear(MAX_FILE_SIZE, 4096),nn.ReLU())
        self.relu = nn.ReLU()
        self.linear2 = nn.Linear(HIDDEN_NEURON, num_classes)
        self.sigmoid = nn.Sigmoid()
        self.loss = nn.BCELoss()
        self.bn_input = nn.BatchNorm1d(MAX_FILE_SIZE, momentum=0.5)
        self.bn_hidden = nn.BatchNorm1d(HIDDEN_NEURON, momentum=0.5)

    def forward(self, x, y=None):
        x = self.bn_input(x)
        x = self.linear1(x)
        x = self.bn_hidden(x)
        x = self.relu(x)
        x = self.linear2(x)
        x = self.sigmoid(x)
        if(y == None):
            return x
        else:
            loss = self.loss(x,y)
            l2_loss = 0.0
            for param in self.parameters():
                l2_loss += torch.norm(param)**2
            loss += self.l2_reg * l2_loss * 0.001
            acc = accur_1(y,x)
            return loss, acc

    '''
        calculate gradients: single file and single neuron
    '''
    def pre_grad_single(self, x, index=0):
        x = self.bn_input(x)
        x = self.linear1(x)
        x = self.bn_hidden(x)
        x = self.relu(x)
        x = self.linear2(x)
        x = self.sigmoid(x)
        return x[index]

    '''
        calculate gradients: batch files and single neuron
    '''
    def pre_grad_batch(self, x, neuron=0):
        x = self.bn_input(x)
        x = self.linear1(x)
        x = self.bn_hidden(x)
        x = self.relu(x)
        x = self.linear2(x)
        x = self.sigmoid(x) # shape (batch_size, num_classes)
        x = x[:, neuron] # shape (batch_size,)
        x = x.view(-1,1) # shape (batch_size, 1)
        return x

def train(model,X,y):
    train_x,test_x,train_y,test_y = train_test_split(X,y,test_size=0.2,random_state=rand_seed)
    train_x = train_x.to(device)
    train_y = train_y.to(device)
    test_x = test_x.to(device)
    test_y = test_y.to(device)

    train_dataset = TensorDataset(train_x, train_y)
    train_loader = DataLoader(dataset=train_dataset, batch_size=BATCH_SIZE, shuffle=True, drop_last=True)

    learning_rate = 1e-5
    opt = optim.Adam(model.parameters(), lr = learning_rate)

    for epoch in range(EPOCH):
        epoch_start_time = time.time()
        losses = []
        accs = []

        for b_x,b_y in train_loader:
            b_x.requires_grad = True
            opt.zero_grad()
            loss, acc = model(b_x, b_y)
            loss.backward()
            opt.step()
            accs.append(acc.tolist())
            losses.append(loss.tolist())

        train_loss = np.mean(losses)
        train_acc = np.mean(accs)

        # eval the model
        epoch_duration = time.time() - epoch_start_time
        print(f"Epoch {epoch} took {epoch_duration:.2f} seconds.")
        print("epoch {}: loss {} accuracy {}".format(epoch,train_loss,train_acc))
        model.eval()
        test_loss,test_acc = model(test_x,test_y)
        print("test epoch {}: loss {} accuracy {}".format(epoch,test_loss,test_acc))
        model.train()
    return model

def retrain():
    global DOM_BB_NUM
    while True:
        try:
            X_filenames, X, y, DOM_BB_NUM, DOM_BITS, trainset_balance, dom_bits_levels, trainset_levels = init()
            break
        except:
            print('There is only one label in the trainset! Retrain in 5min!')
            time.sleep(300)
    if not trainset_balance:
        return [],[],[],[],False,[],[]
    print("domBB num: "+str(DOM_BB_NUM))
    print("seeds num: "+str(len(X)))
    model = S2DModel(DOM_BB_NUM)
    model.to(device)
    print(model)
    model = train(model,X,y)
    model.eval()
    seed_list = glob.glob(argvv[1] + '/queue/id*')
    SEEDS = []
    for seed in seed_list:
        with open(seed,'r') as f: 
            f_bytes = np.fromfile(f, dtype=np.uint8)
            if len(f_bytes) > MAX_FILE_SIZE:
                SEEDS.append(f_bytes[:MAX_FILE_SIZE])
            else:
                f_bytes = np.pad(f_bytes,(0,MAX_FILE_SIZE-len(f_bytes)),'constant')
                SEEDS.append(f_bytes)
    seeds = torch.as_tensor(SEEDS, dtype=torch.float32) / 255
    X = seeds.to(device)
    seeds_max_grad = [] # (idx_to_mutate, nb_seeds)
    seeds_grad = []
    for bb in range(DOM_BB_NUM):
        X.requires_grad = True
        model.zero_grad()
        out = model.pre_grad_batch(X,bb) 
        out.backward(torch.ones_like(out))
        grads_value = X.grad.cpu().numpy() # (nb_seeds,)
        seeds_grad.append(np.abs(grads_value))
        this_bb_byte_to_mutate = np.argmax(np.abs(grads_value),axis=1) # (nb_seeds,)
        seeds_max_grad.append(this_bb_byte_to_mutate) 
        X.grad = None
    seeds_max_grad = np.asarray(seeds_max_grad)
    seeds_grad = np.asarray(seeds_grad)

    return X_filenames, seeds_max_grad, DOM_BITS, seeds_grad, True, dom_bits_levels, trainset_levels

if __name__ == '__main__': 
    X_filenames = []
    seeds_max_grad = []
    DOM_BITS = []
    seeds_grad = []
    dom_deepest = []
    dom_second_deepest = []
    dom_first = []
    bytes_to_mutate = []
    dom_bits_levels = []
    bytes_to_mutate_index = 0
    trainset_balance = True
    trainset_levels = []

    while True:
        r_data = myread()
        choice = r_data[:2]
        if choice == b'TA': # receive seed name, return bytes to mutate
            if len(X_filenames) > 0 and len(seeds_max_grad) > 0:
                query = r_data[2:]
                query = query.decode('utf-8')
                query = query.split('/')[-1]
                if query != last_query:
                    print('')
                    print('query: ', query)
                    bytes_to_mutate.clear()
                    bytes_to_mutate_index = 0
                    last_query = query
                answer = -1
                try:
                    seed_index = X_filenames.index(query)
                    dom_bits = DOM_BITS[seed_index]
                    cover_num = 0
                    while cover_num < len(dom_bits) and dom_bits[cover_num] == 1.0:
                        cover_num += 1
                    if cover_num == len(dom_bits):
                        if len(bytes_to_mutate) == 0:
                            print('seed covers '+str(cover_num)+' domBB(s). target reached!')
                            bytes_to_mutate.append(-1)
                    elif cover_num < int(trainset_levels[-1]):
                        if len(bytes_to_mutate) == 0:
                            print('seed covers '+str(cover_num)+' domBB(s), too poor!')
                            bytes_to_mutate.append(-1)
                    elif cover_num == int(trainset_levels[0]) and int(trainset_levels[0]) != int(trainset_levels[1]):
                        if len(bytes_to_mutate) == 0:
                            print('seed covers '+str(cover_num)+' domBB(s), too advanced!')
                            bytes_to_mutate.append(-1)
                    elif cover_num > int(trainset_levels[0]):
                        if len(bytes_to_mutate) == 0:
                            print('seed covers '+str(cover_num)+' domBB(s), too advanced!')
                            bytes_to_mutate.append(-1)
                    else:
                        if len(bytes_to_mutate) == 0:
                            print('seed covers '+str(cover_num)+' domBB(s).')
                            cover_num = trans_vec_index(cover_num,dom_bits_levels)
                            grad_dict_f = {} # byte gradients corresponding to the first dom BB
                            grad_dict_d = {} # byte gradients corresponding to the deepest dom BB
                            grad_dict_s = {} # byte gradients corresponding to the second deepest dom BB
                            for i in range(min(seed_length[query],MAX_FILE_SIZE)):
                                grad_dict_f[i] = seeds_grad[0][seed_index][i]
                                grad_dict_d[i] = seeds_grad[cover_num][seed_index][i]
                                grad_dict_s[i] = seeds_grad[cover_num-1][seed_index][i]
                            dom_first = sorted(grad_dict_f.items(), key=lambda x:x[1], reverse=True) # gradients sorted from large to small
                            dom_deepest = sorted(grad_dict_d.items(), key=lambda x:x[1], reverse=True)                       
                            dom_second_deepest = sorted(grad_dict_s.items(), key=lambda x:x[1], reverse=True)
                            for i in range(min(seed_length[query],MAX_FILE_SIZE)):
                                dom_first[i] = dom_first[i][0]
                                dom_deepest[i] = dom_deepest[i][0]  
                                dom_second_deepest[i] = dom_second_deepest[i][0]
                            for i in range(len(dom_deepest)):
                                if dom_first.index(dom_deepest[i]) > i and dom_second_deepest.index(dom_deepest[i]) >= i:
                                    bytes_to_mutate.append(dom_deepest[i])
                                    if len(bytes_to_mutate) == 20:
                                        break
                            print(bytes_to_mutate)
                        if bytes_to_mutate_index < len(bytes_to_mutate):
                            answer = bytes_to_mutate[bytes_to_mutate_index]
                        elif bytes_to_mutate_index == len(bytes_to_mutate):
                            print('no more potential edges to mutate!')
                        bytes_to_mutate_index += 1
                except:
                    if bytes_to_mutate_index == 0:
                        if query not in X_filenames:
                            if query in poor_seeds:
                                print('The seed covers no dom edge!')
                            else:
                                print('The seed has not been included!')
                        else:
                            print('Maybe there is a bug!')
                        bytes_to_mutate_index += 1
                    # send back MAX, let fuzzer random choice
                if query not in seed_bytes_to_mutate.keys():
                    seed_bytes_to_mutate[query] = []
                if answer in seed_bytes_to_mutate[query]:
                    answer = -1
                else:
                    seed_bytes_to_mutate[query].append(answer)
                if answer != -1:
                    print(answer)
                mywrite(str(answer)+'\x00')
            else:
                if trainset_balance:
                    info('model not trained, continue')
                    mywrite(str(-1)+'\x00')
                else:
                    if new_train:
                        info('trainset unbalanced, generate more!')
                        new_train = False
                    mywrite(str(-2)+'\x00')

        elif choice == b'RE':  # Retrain
            # TODO: retrain
            new_train = True
            if train_last_time == 0:
                info('first trainset generation!')
                train_last_time = time.time()
            else:
                info('last trainset generation was ' + str(round(time.time() - train_last_time)) + 's ago!')
                train_last_time = time.time()
            shm_hold()
            X_filenames, seeds_max_grad,DOM_BITS,seeds_grad,trainset_balance,dom_bits_levels,trainset_levels = retrain()
            shm_unlock()

        elif choice == b'ST': # init fuzzer
            info('START FUZZ')
            shm_unlock()
