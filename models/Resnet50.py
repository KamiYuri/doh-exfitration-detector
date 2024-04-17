# Import the necessary modules
import tensorflow as tf
from keras import layers, models

# Define a function to create a keras model with resnet50 and dropout
def create_keras_model(NUM_FEATURE, NUM_CLASS):
  # Load the resnet50 base model without the top layer
  base_model = tf.keras.applications.ResNet50(
    include_top=False,
    weights="imagenet",
    input_shape=(NUM_FEATURE, NUM_FEATURE, 3)
  )
  # Freeze the base model layers
  base_model.trainable = False
  # Add a global average pooling layer after the base model
  x = layers.GlobalAveragePooling2D()(base_model.output)
  # Add a bottleneck layer with 256 units and relu activation
  x = layers.Dense(256, activation="relu")(x)
  # Add a dropout layer with rate 0.5
  x = layers.Dropout(0.5)(x)
  # Add a final output layer with softmax activation and NUM_CLASS units
  output = layers.Dense(NUM_CLASS, activation="softmax")(x)
  # Create and return the keras model
  model = models.Model(inputs=base_model.input, outputs=output)
  return model