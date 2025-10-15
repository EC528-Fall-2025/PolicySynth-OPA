from setuptools import setup, find_packages

setup(
    name="psynth",  # policysynth -> psynth
    version="0.1.0",
    packages=find_packages(),
    py_modules=["cli"],
    install_requires=[
        "boto3",
        "botocore",
    ],
    entry_points={
        'console_scripts': [
            'psynth=cli:main',
        ],
    },
    author="ecaa",
    description="OPA policiy synthesizer",
    python_requires='>=3.7',
)
