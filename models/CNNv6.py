from tensorflow import keras
from keras.layers import TimeDistributed, Conv1D, MaxPool1D, Flatten, LSTM, Dense, AveragePooling1D,Dropout
from keras.models import Sequential
from keras.regularizers import l2

def create_keras_model(NUM_FEATURE, NUM_CLASSES):

    model = Sequential()
    model.add(Conv1D(input_shape=(NUM_FEATURE, 1), filters=32,
              kernel_size=(1), strides=1, padding='same', activation='relu',kernel_regularizer=l2(0.1),bias_regularizer=l2(0.1)))
    model.add(MaxPool1D(pool_size=3, strides=3,padding='same'))
    model.add(Flatten())
    model.add(Dense(32,kernel_regularizer=l2(0.1),bias_regularizer=l2(0.1),activation='relu'))
    model.add(Dropout(0.5))
    model.add(Dense(NUM_CLASSES))

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
