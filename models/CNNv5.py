from tensorflow import keras
from keras.layers import TimeDistributed, Conv1D, MaxPool1D, Flatten, LSTM, Dense, AveragePooling1D
from keras.models import Sequential


def create_keras_model(NUM_FEATURE, NUM_CLASSES):

    model = Sequential()
    model.add(Conv1D(input_shape=(NUM_FEATURE, 1), filters=32,
              kernel_size=(25), strides=1, padding='same', activation='relu'))
    model.add(MaxPool1D(pool_size=3, strides=3,padding='same'))
    model.add(Conv1D(filters=64, kernel_size=(25),
              strides=1, padding='same', activation='relu'))
    model.add(MaxPool1D(pool_size=3, strides=3,padding='same'))
    model.add(Flatten())
    model.add(Dense(1024))
    model.add(Dense(NUM_CLASSES,activation='softmax'))

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
