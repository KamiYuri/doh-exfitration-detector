from email.header import decode_header
from tensorflow import keras
from keras.layers import TimeDistributed, Conv1D, MaxPool1D, Flatten, LSTM, Dense, AveragePooling1D
from keras.models import Sequential


def create_keras_model(NUM_FEATURE,NUM_CLASSES):

    model = Sequential()
    model.add(Conv1D(64, (3), input_shape=(NUM_FEATURE,1), activation='relu'))
    model.add(Conv1D(128, (3), activation='relu'))
    model.add(AveragePooling1D(2))
    model.add(Flatten())
    model.add(Dense(128, activation='relu'))
    model.add(Dense(64, activation='relu'))
    model.add(Dense(NUM_CLASSES, activation='softmax'))

    # model = Sequential([
    #     Conv2D(32, (3, 3), activation='relu', input_shape=(1, 100)),
    #     MaxPool2D(pool_size=(2, 2)),
    #     Conv2D(64, (3, 3), activation='relu'),
    #     MaxPool2D(pool_size=(2, 2)),
    #     Flatten(),
    #     Dense(512, activation='relu'),
    #     Dense(10, activation='softmax')
    # ])
    return model
