# plugins/attacks/permissions/setup.py
from setuptools import setup, find_packages

setup(
    name="cerberus-permission-attacks",
    version="2.0.0",
    description="Comprehensive permission-based privilege escalation framework",
    author="Cerberus AI Security Team",
    packages=find_packages(),
    install_requires=[
        'pydantic>=2.0',
        'networkx>=3.0',
        'scikit-learn>=1.3',
        'numpy>=1.24',
        'cryptography>=41.0',
        'PyJWT>=2.8',
        'pymysql>=1.1',
        'psycopg2-binary>=2.9',
        'boto3>=1.28',
        'azure-identity>=1.14',
        'google-cloud-iam>=2.13',
        'kubernetes>=28.0',
        'docker>=6.1',
    ],
    python_requires='>=3.9',
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Information Technology',
        'Topic :: Security',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
    ],
)