from setuptools import setup, find_packages

setup(
    name="policysynth",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        "boto3",
        "botocore",
    ],
    entry_points={
        'console_scripts': [
            'policysynth=src.cli:main',
        ],
    },
    author="ecaa",
    description="OPA policiy sunthesizer",
    python_requires='>=3.7',
)