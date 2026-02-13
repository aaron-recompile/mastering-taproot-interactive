# Jupyter Notebooks for "Mastering Taproot"

## Overview

This directory contains the Jupyter Notebook version of *Mastering Taproot*, combining the book's theory and code examples into an interactive learning environment.

## Design Goals

1. **Theory + Practice**: Markdown explanations with runnable code
2. **Stay in sync**: With the main book repository
3. **Interactive learning**: Readers can run code, modify parameters, and observe results

## Directory Structure

```
notebooks/
└── en/                      # English notebooks
    ├── Chapter_01_Private_Keys.ipynb
    ├── Chapter_02_Bitcoin_Script_Fundamentals.ipynb
    └── ...
```

## Quick Start

### 1. Install dependencies

```bash
pip install jupyter notebook
pip install -r ../requirements.txt
```

### 2. Launch Jupyter

```bash
cd notebooks/en
jupyter notebook
```

Or use **Binder**: click the Launch Binder button on [bitcoincoding.dev](https://bitcoincoding.dev).

### 3. Open a chapter

Click `Chapter_01_Private_Keys.ipynb` to start.

## Notebook Structure

Each notebook follows:

1. **Header** — Chapter title and reference info
2. **Introduction** — Overview and learning objectives
3. **Theory Sections** — Markdown explanations
4. **Code Examples** — Runnable code cells
5. **Exercises** — Optional practice
6. **Summary** — Chapter wrap-up

## For Learners

1. **Learn in order**: Start from Chapter 1
2. **Run the code**: Run the first cell of each chapter first to load imports
3. **Experiment**: Change parameters and observe results
4. **Complete exercises**: Work through the Exercise sections

## For Developers

1. **Keep in sync**: Update notebooks when the book or `examples/` code changes
2. **Test execution**: Ensure all code cells run
3. **Verify output**: Check results match the book's examples

## Notes

- Dependencies: See `../requirements.txt` (bitcoin-utils, btcaaron)
- Binder: Run the first code cell of each chapter first to load the environment

---

**Last updated**: 2025-02-12
