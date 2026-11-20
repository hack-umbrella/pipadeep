# 效果图目录

README 的「效果图」章节引用这里的 5 张图。**按下面的文件名放入即可，无需改 README。**

| 文件名 | 截什么 | 建议 |
| :-- | :-- | :-- |
| `01-explore.png` | 「渗透」面板 → **探索链路**页，节点与语义边清晰可见 | 整窗截图，含左侧会话栏与右侧面板 |
| `02-findings.png` | **漏洞**页列表 + 选中一条的详情（严重度、影响资产、复现步骤） | 建议选一条 high/critical |
| `03-report.png` | **报告**视图，能看出「HTTP 流量」小节内联了请求/响应 | 滚到含请求头/响应体的位置 |
| `04-retest.png` | **复测**子页签，含「已修复 / 仍存在 / 新发现 / 回归」分组 | 最好有一轮基线做对比 |
| `05-assets.png` | **资产**页（列表或拓扑图） | 拓扑图更有辨识度 |

## 截图要求

- 格式 PNG，宽度建议 1600–2400px（2x 屏直接截即可，GitHub 会自动缩放）
- **脱敏**：真实目标域名/IP、Cookie、Authorization、身份证/手机号等一律打码或替换
- 不要包含本机绝对路径、会话 ID、内部 errno 等无关信息
- 只截授权范围内的演示环境

## 截完怎么提交

```bash
cd /path/to/pipadeep-llm
cp ~/Desktop/01-explore.png ~/Desktop/02-findings.png \
   ~/Desktop/03-report.png ~/Desktop/04-retest.png ~/Desktop/05-assets.png \
   docs/screenshots/
git add docs/screenshots && git commit -m "docs: add real usage screenshots" && git push
```

> 若某张还没准备好，可以先只放已有的几张：README 里缺图的引用会显示为破图，
> 建议**要么全放，要么临时把缺失那行注释掉**。
