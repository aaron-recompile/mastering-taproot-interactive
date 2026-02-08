# Jupyter Notebooks for "Mastering Taproot"

## 📖 概述

本目录包含《Mastering Taproot》的 Jupyter Notebook 版本，将书籍的理论讲解和代码示例整合为交互式学习环境。

## 🎯 设计目标

1. **理论 + 实践一体化**：Markdown 讲解 + 可执行代码
2. **保持同步**：与 `book/manuscript/` 和 `code/chapterXX/` 同步更新
3. **交互式学习**：读者可以直接运行代码，修改参数，观察结果

## 📁 目录结构

```
notebooks/
├── en/                      # 英文版 Notebooks
│   ├── Chapter_01_Private_Keys.ipynb
│   ├── Chapter_02_Bitcoin_Script.ipynb
│   └── ...
├── zh-Hans/                 # 中文版 Notebooks
│   ├── Chapter_01_私钥与地址.ipynb
│   └── ...
└── shared/                  # 共享资源
    └── images/              # 图片资源（从 book/manuscript/resources/ 链接）
```

## 🚀 快速开始

### 1. 安装依赖

```bash
# 安装 Jupyter
pip install jupyter notebook

# 安装书籍代码依赖（每个章节的 requirements.txt）
pip install -r ../code/chapter01/requirements.txt
```

### 2. 启动 Jupyter

```bash
cd notebooks/en
jupyter notebook
```

### 3. 打开章节

点击 `Chapter_01_Private_Keys.ipynb` 开始学习。

## 📝 Notebook 结构

每个 Notebook 遵循以下结构：

1. **Header** - 章节标题、引用信息
2. **Introduction** - 章节概述、学习目标
3. **Theory Sections** - 理论讲解（Markdown cells）
4. **Code Examples** - 可执行代码（Code cells）
5. **Exercises** - 练习题（可选）
6. **Summary** - 章节总结

## 🔄 同步机制

### 当前状态：手动同步

- 书籍更新后，手动运行转换脚本
- 检查生成的 Notebook
- 提交到 Git

### 未来计划：自动同步

- Git hooks 自动检测变化
- CI/CD 自动转换并更新

## 🛠️ 转换工具

转换工具位于 `tools/notebook_converter_example.py`。

**使用示例：**

```bash
cd tools
python notebook_converter_example.py
```

## 📚 使用建议

### 对于学习者

1. **按顺序学习**：从 Chapter 1 开始，逐步深入
2. **运行代码**：不要只看，要运行并观察输出
3. **修改实验**：尝试修改参数，观察变化
4. **完成练习**：每章的 Exercise 部分要动手完成

### 对于开发者

1. **保持同步**：更新书籍或代码后，记得更新 Notebook
2. **测试执行**：确保所有代码 cell 可以正常运行
3. **检查输出**：验证输出结果与书籍中的示例一致

## ⚠️ 注意事项

1. **路径问题**：Notebook 中的代码引用 `../code/chapterXX/` 路径，确保在正确目录运行
2. **依赖安装**：每个章节可能需要不同的依赖，参考 `code/chapterXX/requirements.txt`
3. **网络环境**：某些示例需要连接 Bitcoin 网络（testnet/mainnet）

## 🔗 相关资源

- **书籍原文**：`../book/manuscript/`
- **代码示例**：`../code/chapterXX/`
- **转换框架**：`../NOTEBOOK_FRAMEWORK.md`
- **转换工具**：`../tools/notebook_converter_example.py`

## 📝 待办事项

- [ ] 完成所有章节的 Notebook 转换
- [ ] 实现自动同步机制
- [ ] 添加交互式可视化
- [ ] 添加练习自动检查
- [ ] 发布到 Jupyter Book 或 Binder

---

**最后更新**: 2025-12-05

