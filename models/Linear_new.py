from email.header import decode_header
from statistics import mode
from tensorflow import keras
from keras.layers import TimeDistributed, Conv1D, MaxPool1D, Flatten, LSTM, Dense, Dropout,InputLayer
from keras.models import Sequential


def create_keras_model(NUM_FEATURE,NUM_CLASSES):
    model = Sequential()
    model.add(InputLayer(input_shape=(NUM_FEATURE,)))
    model.add(Dense(32))
    model.add(Dense(NUM_CLASSES, activation='softmax'))
    
    return model
