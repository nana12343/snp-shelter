import numpy as np
from sklearn.datasets import make_classification
from sklearn.model_selection import train_test_split
from sklearn.neural_network import MLPClassifier
from sklearn.metrics import accuracy_score, f1_score
import time
import sys

def test_training_time(n_samples, n_features, n_classes):
    # 确保参数设置符合要求
    n_clusters_per_class = max(2, n_classes // 2)
    n_informative = min(n_features, n_classes * n_clusters_per_class)
    
    # 生成分类数据
    X, y = make_classification(
        n_samples=n_samples,
        n_features=n_features,
        n_classes=n_classes,
        n_clusters_per_class=n_clusters_per_class,
        n_informative=n_informative,
        random_state=42
    )

    # 划分训练集和测试集
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)

    # 创建多层感知机分类器
    model = MLPClassifier(hidden_layer_sizes=(100, 50), max_iter=500, random_state=42)

    # 记录训练开始时间
    start_time = time.time()

    # 训练模型
    model.fit(X_train, y_train)

    # 记录训练结束时间
    end_time = time.time()

    # 计算训练时间
    training_time = end_time - start_time

    # 进行预测
    y_pred_train = model.predict(X_train)
    y_pred_test = model.predict(X_test)

    # 计算训练集和测试集的准确率和 F1 分数
    accuracy_train = accuracy_score(y_train, y_pred_train)
    accuracy_test = accuracy_score(y_test, y_pred_test)
    f1_train = f1_score(y_train, y_pred_train, average='weighted')
    f1_test = f1_score(y_test, y_pred_test, average='weighted')

    return training_time, accuracy_train, accuracy_test, f1_train, f1_test

if __name__ == "__main__":
    data_sizes = [1000, 5000, 10000, 50000]  # 测试数据量
    n_features = 30  # 特征数量
    n_classes = 5    # 类别数量

    for n_samples in data_sizes:
        time_taken, accuracy_train, accuracy_test, f1_train, f1_test = test_training_time(n_samples, n_features, n_classes)
        print(f"Data size: {n_samples}, Time taken: {time_taken:.4f} seconds")
        print(f"Training Accuracy: {accuracy_train:.4f}, Testing Accuracy: {accuracy_test:.4f}")
        print(f"Training F1 Score: {f1_train:.4f}, Testing F1 Score: {f1_test:.4f}")
        print()
        sys.stdout.flush()
