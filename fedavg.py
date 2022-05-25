import numpy as np
import matplotlib.pyplot as plt
#import cv2
from math import pi
import numpy as np
import matplotlib.pyplot as plt
from tensorflow.keras.models import Model, Sequential
from tensorflow.keras.layers import Input, Convolution2D, ZeroPadding2D, MaxPooling2D, Flatten, Dense, Dropout, Activation
from PIL import Image
import numpy as np
#from tensorflow.keras.applications.imagenet_utils import preprocess_input
from tensorflow.keras.preprocessing import image
import matplotlib.pyplot as plt
from os import walk
import pandas as pd
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense
from tensorflow.keras.layers import LSTM,Dropout,BatchNormalization,Masking,Embedding
from numpy import array
from tensorflow.keras.models import load_model
import matplotlib.pyplot as plt
from sklearn import preprocessing
from matplotlib import pyplot
import tensorflow as tf
# return training data
import scipy
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import MinMaxScaler
import imageio as im
import os
import statsmodels.api as sm
from sklearn.neural_network import MLPRegressor,MLPClassifier
from sklearn.model_selection import cross_val_predict
from sklearn.metrics import mean_squared_error
from sklearn.model_selection import GridSearchCV
import pickle
import os
from numpy import loadtxt
import copy
import pickle
import numpy as np
from numpy.lib import math
from sklearn.linear_model import LinearRegression, SGDRegressor
from statsmodels.regression import linear_model
import time
import copy
import os
import cv2,time
import numpy as np
from PIL import Image
import copy
from PIL import Image
import glob
import numpy as np
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense
from tensorflow.keras.utils import to_categorical
from sklearn.model_selection import cross_val_score
from sklearn.model_selection import KFold
from sklearn.preprocessing import LabelEncoder
from sklearn import datasets, metrics
from sklearn.metrics import accuracy_score
import random
from tensorflow.keras import regularizers
from sklearn.preprocessing.data import StandardScaler
import tensorflow as tf
from sklearn.utils import shuffle
from sklearn.metrics import classification_report
import pandas as pd 
from sklearn.utils import shuffle
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense
from tensorflow.keras.utils import to_categorical
from sklearn.preprocessing import scale
from tqdm import tqdm    
import copy
import torch
from torch import nn
from tensorflow.keras import backend
from tensorflow.keras.optimizers import SGD

comms_round=
client_names=[]



#Enable all GPUs

config = tf.compat.v1.ConfigProto()
config.gpu_options.allow_growth = True
sess = tf.compat.v1.Session(config=config)




def select_sub(id):
    
    df_user =  []     
    df_user_y =  []

    return df_user,df_user_y

def build_global_model(avg,get_model):
    model = Sequential()
    
    model.add(Dense(30, input_dim=3, activation='relu'))
    model.add(Dense(12,activation='softmax'))

    model.compile(
    optimizer='Adam',
    loss='categorical_crossentropy', 
    metrics=['accuracy'],
    )
    if(get_model==False):
        model.set_weights(avg)
   
    return model
    
def write_weight_to_file(w,cl_id,comm_r,tr):
    w_new=[]
    f=open('--','w')
    for x in w[0]:
        for a in x:
            w_new.append(a)
            f.write(str(a))
            f.write('\n')
    for x in w[1]:
        w_new.append(x)
        f.write(str(x))
        f.write('\n')
    
    for x in w[2]:
        for a in x:
            w_new.append(a)
            f.write(str(a))
            f.write('\n')
            
    for x in w[3]:
        w_new.append(x)
        f.write(str(x))
        f.write('\n')
    f.close
  
def load_weight_from_file(cl_id,comm_r,tr):
    X0,y0=select_sub(1)
    X0, y0 = shuffle(X0, y0, random_state=10)
    y0 = to_categorical(y0)
    n_cols = X0.shape[1]

    model = Sequential()
    
    model.add(Dense(30, input_dim=n_cols, activation='relu'))
    model.add(Dense(12,activation='softmax'))
 
    model.compile(
    optimizer='Adam',
    loss='categorical_crossentropy',
    metrics=['accuracy'],
    )
    
    w=model.get_weights()
    #return w

    w_new=[]
    
    f = open('--', "r")

    for x in f:
        w_new.append(float(x))
    f.close
    i=0
    j=0
    for x in w[0]:
        
        k=0
        for a in x:
            old=w[0][j][k]
            w[0][j][k]=(w_new[i])
            i=i+1
            k=k+1

        j=j+1
    k=0
    for x in w[1]:
        
        w[1][k]=w_new[i]
        k=k+1
        i=i+1

    j=0
    for x in w[2]:
        
        k=0
        for a in x:
            w[2][j][k]=w_new[i]
            k=k+1
            i=i+1
        j=j+1
    k=0
    for x in w[3]:
        
        w[3][k]=w_new[i]
        k=k+1
        i=i+1

    return w
    
    
def get_weights(c_id,g_w,comm_r,tr):

    
    X0,y0=select_sub(c_id)
    
    X_val=[]
    y_val=[]
  
    import sklearn

    X0=X0[]
    y0=y0[]
    

    y_val = to_categorical(y_val)
    y0 = to_categorical(y0)

    n_cols = X0.shape[1]
    from tensorflow.keras.layers import BatchNormalization
    model = Sequential()
    
    model.add(Dense(30, input_dim=n_cols, activation='relu'))
    model.add(Dense(12,activation='softmax'))
    lr = 0.01
    optimizer = SGD(lr=lr, 
    decay=lr / comms_round, 
    momentum=0.9
    )
    model.compile(
    optimizer='Adam',
    loss='categorical_crossentropy', 
    metrics=['accuracy'],
    )
    
    model.set_weights(g_w)
    model.compile(
    optimizer='Adam',
    loss='categorical_crossentropy', 
    metrics=['accuracy'],
    )
    history =model.fit(X0,y0,epochs=40,    shuffle=True ,verbose=False)
    
    
    #return model.get_weights()
    write_weight_to_file(model.get_weights(),c_id,comm_r,tr)
    #print(model.get_weights())
    #return model.get_weights()
    w=load_weight_from_file(c_id,comm_r,tr)
    
    model.set_weights(w) 
    
    return model.get_weights()
    #from tensorflow.keras import backend as K
    #get_3rd_layer_output = K.function([model.layers[0].input],
    #                                [model.layers[1].output])
    #layer_output = get_3rd_layer_output([array(X)])[0]
    
    #return pd.DataFrame(np.array(layer_output))#layer_output
    
    
def FedAvg():

    # Training data
    X_t=[]
    y_t=[]
    X_t, y_t = shuffle(X_t, y_t, random_state=10)


    y_t = to_categorical(y_t)

    for tr in range(1,5):

        print('Trial N= '+ str(tr))
        acc_arr=[]
        loss_arr=[]
        global_model=build_global_model(0,True)
        score=global_model.evaluate(X_t,y_t)
        print(score)
        for comm_round in range(0,comms_round):
        
            global_weights = global_model.get_weights()
            
            #get weights 
            s_weights = list()

            
            #For each client
            for client in client_names:
     
                print(client)
                client_model_w=get_weights(client,global_weights,comm_round,tr)
                s_weights.append(client_model_w)
            average_weights = np.mean(s_weights, axis=0)
            global_model.set_weights(average_weights)

                
            global_acc, global_loss = test_model(X_t, y_t, global_model,comm_round)

            acc_arr.append(global_acc)
            loss_arr.append(global_loss)


            print('---------')
            print(global_acc,global_loss)
            
            with open('acc_loss_global/--', 'w') as f:
                for item in acc_arr:
                    f.write("%s\n" % item)
                
            with open('acc_loss_global/--', 'w') as f:
                for item in loss_arr:
                    f.write("%s\n" % item)
                
            f.close()

    
if __name__ == '__main__':
    FedAvg()
    sys.exit(main())  