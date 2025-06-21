#!/usr/bin/env python
# coding: utf-8

# # Multilayer perceptron example
# 
# This Jupyter notebook has as goal to show the use the Multilayer-perceptron class `mlp.py` provided in this repository. The implementation of the MLP has didactic purposes in other words is not optimized, but well commented. It is mostly based on the lectures for weeks 4 and 5 (neural networks) in the the MOOC [Machine Learning](https://www.coursera.org/learn/machine-learning#%20) taught by from Andrew Ng and notes from the chapter 6 (deep forward networks) from the [Deep Learning](http://www.deeplearningbook.org/).  
# 

# In[1]:


# get_ipython().run_line_magic('matplotlib', 'notebook')
# get_ipython().run_line_magic('matplotlib', 'auto')

from PIL import Image
import numpy as np
import pickle, gzip
import mlp
import matplotlib.pyplot as plt
import os
import urllib.request
import cv2
import struct
import random

def float2bytearray(data):
    # Convert float32 to bytearray
    data = np.array(data, dtype=np.float32)
    data = data.tobytes()
    # print(data)
    return data

def recover_data(data, dump_num = 0):
    if dump_num == 0:
        dump_num = int(len(data) // (28 * 28 * 4))
    origin_figure = list()
    figure_list = list()
    print(f"dump num is: {dump_num}")
    for f in range(dump_num):
        data_use = data[f * 28 * 28 * 4 : (f + 1) * 28 * 28 * 4]
        data_use = bytearray(data_use)
        origin_figure.append(data_use.copy())
        for i in range(0, len(data_use), 16):
            group1 = data_use[i : i+4]
            group2 = data_use[i+4 : i+8]
            group3 = data_use[i+8 : i+12]
            group4 = data_use[i+12 : i+16]
            eq1 = [np.array_equal(group1, group) for group in [group2, group3, group4]]
            eq1_num = sum(eq1)
            eq2 = [np.array_equal(group2, group) for group in [group1, group3, group4]]
            eq2_num = sum(eq2)
            eq3 = [np.array_equal(group3, group) for group in [group1, group2, group4]]
            eq3_num = sum(eq3)
            eq4 = [np.array_equal(group4, group) for group in [group1, group2, group3]]
            eq4_num = sum(eq4)
            if min([eq1_num, eq2_num, eq3_num, eq4_num]) == 3:
                for j in range(4):
                    # data_use[i + j * 4 : i + j * 4 + 4] = 0.0
                    data_use[i + j * 4 : i + j * 4 + 4] = float2bytearray(0.0)
            if min([eq1_num, eq2_num, eq3_num, eq4_num]) == 0 and max([eq1_num, eq2_num, eq3_num, eq4_num]) == 0:
                for j in range(4):
                    # data_use[i + j * 4 : i + j * 4 + 4] = 0.98828125
                    data_use[i + j * 4 : i + j * 4 + 4] = float2bytearray(0.98828125)
            if min([eq1_num, eq2_num, eq3_num, eq4_num]) == 0 and max([eq1_num, eq2_num, eq3_num, eq4_num]) == 2:
                single = [eq1_num, eq2_num, eq3_num, eq4_num].index(0)
                for j in range(4):
                    if single == j:
                        # data_use[i + j *4 : i + j * 4 + 4] = 0.98828125
                        data_use[i + j *4 : i + j * 4 + 4] = float2bytearray(0.98828125)
                    else:
                        # data_use[i + j *4 : i + j * 4 + 4] = 0.0
                        data_use[i + j *4 : i + j * 4 + 4] = float2bytearray(0.0)
            if min([eq1_num, eq2_num, eq3_num, eq4_num]) == 0 and max([eq1_num, eq2_num, eq3_num, eq4_num]) == 1:
                single = [j for j, x in enumerate([eq1_num, eq2_num, eq3_num, eq4_num]) if x == 0]
                double = [j for j, x in enumerate([eq1_num, eq2_num, eq3_num, eq4_num]) if x == 1]
                for j in range(4):
                    if j in single:
                        # data_use[i + j *4 : i + j * 4 + 4] = 0.98828125
                        data_use[i + j *4 : i + j * 4 + 4] = float2bytearray(0.98828125)
                    if j in double:
                        # data_use[i + j *4 : i + j * 4 + 4] = 0.0
                        data_use[i + j *4 : i + j * 4 + 4] = float2bytearray(0.0)
            if min([eq1_num, eq2_num, eq3_num, eq4_num]) == 1 and max([eq1_num, eq2_num, eq3_num, eq4_num]) == 1:
                double = [[0, eq1.index(1)+1], list(set(range(4)) - set([0, eq1.index(1)+1]))]
                chose_0 = double[random.randint(0, 1)]
                for j in range(4):
                    if j in chose_0:
                        # data_use[i + j *4 : i + j * 4 + 4] = 0.0
                        data_use[i + j *4 : i + j * 4 + 4] = float2bytearray(0.0)
                    else:
                        # data_use[i + j *4 : i + j * 4 + 4] = 0.98828125
                        data_use[i + j *4 : i + j * 4 + 4] = float2bytearray(0.98828125)
        figure_list.append(data_use)
    return origin_figure, figure_list

# ## 1. Loading dataset
# The dataset utilzied for this example can be downloaded from [http://deeplearning.net/data/mnist/mnist.pkl.gz](http://deeplearning.net/data/mnist/mnist.pkl.gz) and consist of a subset (20k examples) of the famous [MNIST dataset](https://en.wikipedia.org/wiki/MNIST_database). 

# In[2]:


# Download MNIST data if needed  
mnist_filename = 'mnist.pkl.gz'
if not os.path.exists(mnist_filename):    
    ulr_mnist = 'http://deeplearning.net/data/mnist/mnist.pkl.gz'
    urllib.request.urlretrieve(ulr_mnist, mnist_filename)

# As 'mnist.pkl.gz' was created in Python2, 'latin1' encoding is needed to loaded in Python3
with gzip.open(mnist_filename, 'rb') as f:
    train_set, valid_set, test_set = pickle.load(f, encoding='latin1')


with open('leak.bin', 'rb') as f:
    # 读取文件中的数据，并将其转换为float32类型的numpy数组
    leak_data = f.read(28*28*4*5000)

origin_figure, figure_list = recover_data(leak_data, 5000)
# Test Set
label_figure = train_set[1]
for i in range(len(figure_list)):
    if not os.path.exists('of_dir'):
        os.makedirs('of_dir')
    if not os.path.exists('if_dir'):
        os.makedirs('if_dir')
    f = origin_figure[i]
    array = np.frombuffer(f, dtype=np.float32)
    array.resize((28, 28))
    # print(I)
    im = Image.fromarray((array*256).astype('uint8'))
    im.save(f'./of_dir/of_{i}_{label_figure[i]}.png')
    f = figure_list[i]
    array = np.frombuffer(f, dtype=np.float32)
    array.resize((28, 28))
    # print(I)
    im = Image.fromarray((array*256).astype('uint8'))
    im.save(f'./if_dir/if_{i}_{label_figure[i]}.png')

test_tiny = 'tiny-imagenet-200/train/n01443537/images/n01443537_0.JPEG'

image_rgb = cv2.imread(test_tiny)

img_gray = cv2.cvtColor(image_rgb, cv2.COLOR_BGRA2GRAY)
img_gray_normalized = cv2.normalize(img_gray, None, alpha=0, beta=1, norm_type=cv2.NORM_MINMAX, dtype=cv2.CV_32F)
img_gray_normalized = np.reshape(img_gray_normalized, [1, 64*64])

# The dataset contains 70K examples divided as: 50k for training, 10k for validation and 10k for testing.
# Each example is a 28x28 pixel grayimages containing a digit. Some examples of the database:


# Plot random examples
examples = np.random.randint(10000, size=8)
n_examples = len(examples)
# plt.figure()
for ix_example in range(n_examples):
    tmp = np.reshape(train_set[0][examples[ix_example],:], [28,28])
    ax = plt.subplot(1,n_examples, ix_example + 1)
    ax.set_yticklabels([])
    ax.set_xticklabels([])
    plt.title(str(train_set[1][examples[ix_example]]))
    plt.imshow(tmp, cmap='gray')


# For sake of time, the MLP is trained with the validation set (10K examples); testing is performed with the test set (10K examples)

# In[4]:


# Training data
train_X = valid_set[0]
train_y = valid_set[1]  
print('Shape of training set: ' + str(train_X.shape))

# change y [1D] to Y [2D] sparse array coding class
n_examples = len(train_y)
labels = np.unique(train_y)
train_Y = np.zeros((n_examples, len(labels)))
for ix_label in range(len(labels)):
    # Find examples with with a Label = lables(ix_label)
    ix_tmp = np.where(train_y == labels[ix_label])[0]
    train_Y[ix_tmp, ix_label] = 1


def byte2np(data):
    # Convert list of bytearrays to numpy array of 784 float32 values
    num_images = len(data)
    print(f"num_images is: {num_images}")
    
    # Initialize empty array to hold all images as 784-length vectors
    images_array = np.empty((num_images, 784), dtype=np.float32)
    
    # Convert each bytearray to float32 numpy array of length 784
    for i, byte_data in enumerate(data):
        # Convert bytearray to numpy array
        img = np.frombuffer(byte_data, dtype=np.float32)
        images_array[i] = img
        
    return images_array

# Test data
# test_O = test_set[0]
test_O = byte2np(origin_figure)
test_I = byte2np(figure_list)
test_y = train_set[1][:len(test_O)]
print('Shape of test set: ' + str(test_O.shape))

# change y [1D] to Y [2D] sparse array coding class
n_examples = len(test_y)
labels = np.unique(test_y)
test_Y = np.zeros((n_examples, len(labels)))
for ix_label in range(len(labels)):
    # Find examples with with a Label = lables(ix_label)
    ix_tmp = np.where(test_y == labels[ix_label])[0]
    test_Y[ix_tmp, ix_label] = 1


# ## 2. Parameters of MLP
#  * __Number of layers__ : 4 (input, hidden1, hidden2 output)
#  * __Elements in layers__ : [784, 25, 10, 10]   
#  * __Activation function__ : Rectified Linear function
#  * __Regularization parameter__ : 1 

# ## 3. Creating MLP object 

# In[5]:


# Creating the MLP object initialize the weights
mlp_classifier = mlp.Mlp(size_layers = [784, 25, 10, 10], 
                         act_funct   = 'relu',
                         reg_lambda  = 0,
                         bias_flag   = True)
print(mlp_classifier)


# ## 4. Training MLP object

# In[6]:


# Training with Backpropagation and 400 iterations
iterations = 400
loss = np.zeros([iterations,1])

for ix in range(iterations):
    mlp_classifier.train(train_X, train_Y, 1)
    Y_hat = mlp_classifier.predict(train_X)
    y_tmp = np.argmax(Y_hat, axis=1)
    y_hat = labels[y_tmp]
    
    loss[ix] = (0.5)*np.square(y_hat - train_y).mean()

# Ploting loss vs iterations
plt.figure()
ix = np.arange(iterations)
plt.plot(ix, loss)

# Training Accuracy
Y_hat = mlp_classifier.predict(train_X)
y_tmp = np.argmax(Y_hat, axis=1)
y_hat = labels[y_tmp]

acc = np.mean(1 * (y_hat == train_y))
print('Training Accuracy: ' + str(acc*100))


# ## 5. Testing MLP

# In[7]:


# Test Accuracy
Y_hat = mlp_classifier.predict(test_O)
y_tmp = np.argmax(Y_hat, axis=1)
y_hat_o = labels[y_tmp]
print(f"y_hat is: {y_hat}")

acc = np.mean(1 * (y_hat_o == test_y))
print('Origin Predict Accuracy: ' + str(acc*100))  

Y_hat = mlp_classifier.predict(test_I)
y_tmp = np.argmax(Y_hat, axis=1)
y_hat_i = labels[y_tmp]

acc = np.mean(1 * (y_hat_i == test_y))
print('Leak Predict Accuracy: ' + str(acc*100))  

predict_not_equal = 0
incorrect_index = list()
O_correct = 0
O_correct_index = list()
I_correct = 0
I_correct_index = list()
for i in range(len(y_hat_o)):
    if y_hat_o[i] != y_hat_i[i]:
        predict_not_equal += 1
        incorrect_index.append((i, y_hat_o[i], y_hat_i[i], test_y[i]))
        if y_hat_o[i] == test_y[i]:
            O_correct += 1
            O_correct_index.append((i, y_hat_o[i], y_hat_i[i], test_y[i]))
        if y_hat_i[i] == test_y[i]:
            I_correct += 1
            I_correct_index.append((i, y_hat_o[i], y_hat_i[i], test_y[i]))
# print(f"predict_not_equal is: {predict_not_equal}, O_correct is: {O_correct}, I_correct is: {I_correct}")
print(f"Images Dataset Recovery Success Rate is: {(len(test_I) - predict_not_equal) / len(test_I) * 100}%")
# print(f"Not success original correct is: {O_correct / predict_not_equal * 100}%")
# print(f"Not success leak correct is: {I_correct / predict_not_equal * 100}%")
# print(f"Incorrect result:")
# for i in incorrect_index:
#     print(f"index is: {i[0]}, origin predict is: {i[1]}, leak predict is: {i[2]}, true is: {i[3]}")
# print(f"O_correct result:")
# for i in O_correct_index:
#     print(f"index is: {i[0]}, origin predict is: {i[1]}, leak predict is: {i[2]}, true is: {i[3]}")
# print(f"I_correct result:")
# for i in I_correct_index:
#     print(f"index is: {i[0]}, origin predict is: {i[1]}, leak predict is: {i[2]}, true is: {i[3]}")

print(f"Finish Recovery")
# In[8]:


# print(test_O.shape)
# ix_example = 1
# tmp = np.reshape(test_O[examples[ix_example],:], [28,28])


# # In[9]:


# # Some test samples, [T]rue labels and [P]redicted labels
# examples = np.random.randint(10000, size=8)
# n_examples = len(examples)
# plt.figure()
# for ix_example in range(n_examples):
#     tmp = np.reshape(test_O[examples[ix_example],:], [28,28])
#     ax = plt.subplot(1,8, ix_example + 1)
#     ax.set_yticklabels([])
#     ax.set_xticklabels([])
#     plt.title('T'+ str(test_y[examples[ix_example]]) + ', P' + str(y_hat[examples[ix_example]]))
#     plt.imshow(tmp, cmap='gray')
    


# # ## 6.  Plotting some weights
# # #### A. Weights from Input layer to Hidden layer 1

# # In[10]:


# w1 = mlp_classifier.theta_weights[0][:,1:]
# plt.figure()
# for ix_w in range(25):
#     tmp = np.reshape(w1[ix_w,:], [28,28])
#     ax = plt.subplot(5,5, ix_w + 1)
#     ax.set_yticklabels([])
#     ax.set_xticklabels([])
#     plt.title(str(ix_w))
#     plt.imshow(1- tmp, cmap='gray')


# # #### B. Weights from Hidden layer 1 to Hidden layer 2

# # In[11]:


# w2 =  mlp_classifier.theta_weights[1][:,1:]
# plt.figure()
# for ix_w in range(10):
#     tmp = np.reshape(w2[ix_w,:], [5,5])
#     ax = plt.subplot(2,5, ix_w + 1)
#     ax.set_yticklabels([])
#     ax.set_xticklabels([])
#     plt.title(str(ix_w))
#     plt.imshow(1- tmp, cmap='gray')


# # #### C. Weights from Hidden layer 2 to Output layer

# # In[12]:


# w3 =  mlp_classifier.theta_weights[2][:,1:]
# plt.figure()
# for ix_w in range(10):
#     tmp = np.reshape(w3[ix_w,:], [1,10])
#     ax = plt.subplot(10,1, ix_w + 1)
#     ax.set_yticklabels([])
#     ax.set_xticklabels([])
#     plt.title(str(ix_w))
#     plt.imshow(1- tmp, cmap='gray')

# # In[ ]:




