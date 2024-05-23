import pickle
from features import feature
import numpy as np
import os
from flask import Flask, request, jsonify
from flask_cors import CORS
# Get the absolute path of the script's directory
script_dir = os.path.dirname(os.path.abspath(__file__))

# Construct absolute paths
model_path = os.path.join(script_dir, 'randomforest_model.pkl')

# Load the model
with open(model_path, 'rb') as f:
    model = pickle.load(f)

app = Flask(__name__)
CORS(app)

@app.route('/predict', methods=['POST'])
def predict():
    url = request.json.get('url')  # Extract URL from JSON data
    print("URL: ", url)
    if not url:
        return jsonify({'error': 'URL not provided'}), 400

    features = feature(url)
    features = np.array(features)[1:]
    features = features.reshape(1, -1)

    prediction = model.predict(features)[0]
    print("Prediction: ", prediction)
    response = {
        'prediction': int(prediction), 
        'msg': 'MALICIOUS' if prediction == 1 else 'SAFE'
    }

    return jsonify(response)

if __name__ == '__main__':
    print('Starting Flask server...')
    app.run(host='localhost', port=5000)
