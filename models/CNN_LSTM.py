from tensorflow import keras
from keras.layers import TimeDistributed, Conv1D, MaxPool1D, Flatten, LSTM, Dense
from keras.models import Sequential


def create_keras_model(x_train, NUM_CLASSES):
    time_steps = 1

    model = Sequential()
    model.add(Conv1D(32, 1, activation="relu",
              input_shape=(time_steps, x_train.shape[2])))
    model.add(MaxPool1D(pool_size=2, padding="same"))
    # #Building the LSTM Model
    model.add(LSTM(units=64, return_sequences=True))
    model.add(Flatten())
    model.add(Dense(32, activation='relu'))
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
