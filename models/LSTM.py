from keras import Sequential
from keras.layers import Conv2D, MaxPool2D, Flatten, Dense
from keras.models import Sequential
from keras.layers import Dense, LSTM

def create_keras_model(x_train):
    time_steps = 1
    # #Building the LSTM Model
    model = Sequential()
    # unit = hidden state
    model.add(LSTM(units=64, input_shape=(time_steps, x_train.shape[2]), return_sequences=True))

    model.add(LSTM(units=128,  return_sequences=True))

    model.add(LSTM(units=64,  return_sequences=False))

    model.add(Dense(16, activation='softmax')) 

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