from tensorflow import keras
from keras.layers import TimeDistributed, Conv1D, MaxPool1D, Flatten, LSTM, Dense, AveragePooling1D, Dropout, Conv2D, MaxPool2D
from keras.models import Sequential
from keras.regularizers import l2


def create_keras_model(NUM_FEATURE, NUM_CLASSES):

    model = Sequential()

    model.add(Conv2D(filters=32, kernel_size=(5, 5), padding='Same',
                     activation='relu', input_shape=(20, NUM_FEATURE, 1)))
    model.add(Conv2D(filters=32, kernel_size=(5, 5), padding='Same',
                     activation='relu',kernel_regularizer=l2(0.1),bias_regularizer=l2(0.1)))
    model.add(MaxPool2D(pool_size=(2, 2)))
    model.add(Conv2D(filters=64, kernel_size=(3, 3), padding='Same',
                     activation='relu',kernel_regularizer=l2(0.1),bias_regularizer=l2(0.1)))
    model.add(Conv2D(filters=64, kernel_size=(3, 3), padding='Same',
                     activation='relu',kernel_regularizer=l2(0.1),bias_regularizer=l2(0.1)))
    model.add(MaxPool2D(pool_size=(2, 2), strides=(2, 2)))
    model.add(Flatten())
    model.add(Dense(256, activation="relu",kernel_regularizer=l2(0.1),bias_regularizer=l2(0.1)))
    model.add(Dense(NUM_CLASSES, activation="softmax"))
    return model
