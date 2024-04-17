from email.header import decode_header
from statistics import mode
from tensorflow import keras
from keras.layers import TimeDistributed, Conv1D, MaxPool1D, Flatten, LSTM, Dense, Dropout,InputLayer
from keras.models import Sequential


def create_keras_model(x_train, NUM_CLASSES):
    time_steps = 1

    model = Sequential()
    model.add(InputLayer(input_shape=(time_steps, x_train.shape[2])))
    model.add(Dense(32))
    model.add(Dense(NUM_CLASSES, activation='softmax'))
    
    return model
