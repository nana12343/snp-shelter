# 使用 Python 官方镜像作为基础镜像
FROM python:3.9-slim

# 设置工作目录
WORKDIR /app

# 复制当前目录中的文件到容器内的工作目录
COPY . /app

# 安装所需的 Python 包
RUN pip install --no-cache-dir scikit-learn numpy -i https://pypi.tuna.tsinghua.edu.cn/simple


# 设置默认命令来运行 Python 脚本
CMD ["python", "ml_test.py"]
