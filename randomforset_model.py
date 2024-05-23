import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import cross_val_score  
from sklearn.metrics import accuracy_score, roc_auc_score, precision_score, recall_score, f1_score, confusion_matrix
import matplotlib.pyplot as plt 
import pickle 


data = pd.read_csv(r"C:\Users\USER\Desktop\projerc(final)\model\final_dataset.csv")
y = data['label']
X = data.drop('label', axis=1)

best_params = {'criterion': 'gini', 'max_depth': 10, 'n_estimators': 300}
rf_model = RandomForestClassifier(random_state=42, **best_params)

# Cross-Validation 
cv_scores = cross_val_score(rf_model, X, y, cv=5, scoring='accuracy') 
print("Cross-Validation Accuracy Scores:", cv_scores)
print("Average Cross-Validation Accuracy:", cv_scores.mean())


rf_model.fit(X, y) 


y_pred = rf_model.predict(X)
accuracy = accuracy_score(y, y_pred)
roc_auc = roc_auc_score(y, y_pred)
precision = precision_score(y, y_pred)
recall = recall_score(y, y_pred)
f1 = f1_score(y, y_pred)
cm = confusion_matrix(y, y_pred)

print("Accuracy :", accuracy)
print("ROC-AUC :", roc_auc)
print("Precision :", precision)
print("Recall :", recall)
print("F1-Score :", f1)
print("Confusion Matrix :\n", cm)

#  Visualization of Confusion Matrix
fig, ax = plt.subplots()
ax.matshow(cm, cmap='coolwarm')


cm_normalized = cm.astype('float') / cm.sum(axis=1)[:, np.newaxis]
for (i, j), z in np.ndenumerate(cm_normalized):
    ax.text(j, i, f"{cm[i, j]} ({z:0.1%})", ha='center', va='center', fontsize=8)

ax.set_xticks(np.arange(2))
ax.set_yticks(np.arange(2))
ax.set_xlabel('Predicted label')
ax.set_ylabel('True label')
ax.set_title('Confusion Matrix for randomforest model') 
plt.show()

# Storing the Model
with open(r"C:\Users\USER\Desktop\projerc(final)\model\randomforest_model.pkl", 'wb') as f:
  pickle.dump(rf_model, f) 