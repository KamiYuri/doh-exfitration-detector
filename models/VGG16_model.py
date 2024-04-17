from tensorflow import keras
from keras import Sequential
from keras.layers import Conv2D, MaxPool2D, Flatten, Dense, Dropout
from keras.applications.vgg16 import VGG16
from keras.applications.vgg16 import preprocess_input

def create_keras_model(NUM_FEATURE, NUM_CLASSES, PACKET_NUM):
    model = VGG16(weights=None, include_top=False, input_shape=(PACKET_NUM,NUM_FEATURE,1), classes=NUM_CLASSES,classifier_activation="softmax")
    return model