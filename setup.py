from setuptools import setup, find_packages

setup(
    name="envmgr",
    version="1.0.0",
    description="命令行环境变量管家 - 管理多项目多环境配置",
    author="envmgr",
    packages=find_packages(),
    entry_points={
        "console_scripts": [
            "envmgr=envmgr.cli:main",
        ],
    },
    python_requires=">=3.8",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
)
