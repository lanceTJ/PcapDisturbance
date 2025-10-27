# pcaplab

这是一个高性能流式PCAP扰动工具包，实现威胁模型I/II：
- 数据包丢失、重传、TCP序列偏移
- 数据包长度伪造、（离线）数据包速率修改占位符
- 支持大型PCAP的流式分块处理
- 目录批量运行器，镜像日期/PCAP目录结构，跳过`encrypted_pcaps`目录

##  安装
```bash
pip install -e .
```

##  扰动 Plan 说明

###  Plan.json 整体结构

`plan.json`是一个JSON数组，每个元素代表一个扰动步骤，按顺序执行：

```json
[
  {
    "type": "扰动类型",
    "pct": "{百分比}",
    "params": {
      "参数名": "参数值"
    }
  }
]
```

###  支持的扰动类型及参数

#####  1. **丢包 (loss)**
```json
{
  "type": "loss",
  "pct": 0.1,
  "params": {}
}
```
- **作用**：随机丢弃指定百分比的数据包
- **参数**：无额外参数
- **示例**：10%的数据包被丢弃

#####  2. **重传 (retransmit/retrans)**
```json
{
  "type": "retransmit",
  "pct": 0.05,
  "params": {}
}
```
- **作用**：复制指定百分比的数据包
- **参数**：无额外参数
- **示例**：5%的数据包被复制一份

#####  3. **乱序 (reorder/jitter)**
```json
{
  "type": "reorder",
  "pct": 1.0,
  "params": {}
}
```
- **作用**：在chunk内打乱数据包顺序
- **参数**：无额外参数
- **注意**：`pct`参数在此类型中可能被忽略，整个chunk都会被打乱

#####  4. **序列号偏移 (seq_offset)**
```json
{
  "type": "seq_offset",
  "pct": 0.02,
  "params": {
    "offset": 500
  }
}
```
- **作用**：修改TCP序列号
- **参数**：
  - `offset`：序列号偏移量（整数）
- **技术细节**：仅影响TCP数据包，自动重新计算校验和

#####  5. **长度伪造 (length_forge)**
```json
{
  "type": "length_forge",
  "pct": 0.01,
  "params": {
    "new_len": 512,
    "pad_byte": "00"
  }
}
```
- **作用**：修改数据包负载长度
- **参数**：
  - `new_len`：目标长度（整数）
  - `pad_byte`：填充字节（十六进制字符串，可选）

###  完整配置示例

```json
[
  {
    "type": "loss",
    "pct": 0.1,
    "params": {}
  },
  {
    "type": "retransmit", 
    "pct": 0.05,
    "params": {}
  },
  {
    "type": "reorder",
    "pct": 1.0,
    "params": {}
  },
  {
    "type": "seq_offset",
    "pct": 0.02,
    "params": {
      "offset": 500
    }
  },
  {
    "type": "length_forge",
    "pct": 0.01,
    "params": {
      "new_len": 512
    }
  }
]
```

###  执行流程说明

#####  1. **选择阶段** (`_select_indices`)
- 按顺序应用`loss`、`retransmit`、`reorder`等扰动
- 纯索引操作，不解析数据包内容
- 统计每个扰动的效果

#####  2. **修改阶段** (`_process_chunk`)
- 仅对需要内容修改的扰动（`seq_offset`、`length_forge`）解析数据包
- 使用零拷贝优化：大部分数据包不解析直接输出

#####  3. **性能优化**
- **快路径**：无内容修改时直接输出原始字节
- **懒解析**：仅对需要修改的数据包进行解析
- **chunk处理**：批量处理提高效率

###  配置建议

#####  网络异常模拟
```json
[
  {"type": "loss", "pct": 0.05, "params": {}},
  {"type": "retransmit", "pct": 0.03, "params": {}},
  {"type": "reorder", "pct": 1.0, "params": {}}
]
```

#####  协议测试
```json
[
  {"type": "seq_offset", "pct": 0.1, "params": {"offset": 1000}},
  {"type": "length_forge", "pct": 0.05, "params": {"new_len": 1500}}
]
```

#####  压力测试  
```json
[
  {"type": "loss", "pct": 0.2, "params": {}},
  {"type": "retransmit", "pct": 0.15, "params": {}},
  {"type": "length_forge", "pct": 0.1, "params": {"new_len": 2048}}
]
```

###  注意事项

1. **顺序重要性**：扰动按数组顺序执行，前一步的输出作为下一步的输入
2. **百分比叠加**：多个扰动可能作用于同一个数据包
3. **性能考虑**：内容修改类扰动（如`length_forge`）会触发数据包解析，影响性能
4. **种子稳定性**：相同配置和种子会产生相同的扰动结果，便于测试复现

这种设计提供了灵活的扰动组合能力，可以模拟各种复杂的网络环境和攻击场景。