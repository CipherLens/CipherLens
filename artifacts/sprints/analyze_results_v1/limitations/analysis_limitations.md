# Analysis Limitations

- 本轮 mutation matrix 是 bounded，不代表完整 fuzzing。
- normal_exit 不等于证明无漏洞。
- 无 sanitizer 输出只说明本轮 case 未触发 ASan/UBSan。
- parser accept/reject divergence 需要 harness 输出或更细 oracle 才能判断。
- 目前只覆盖 OpenSSL target。
- mbedTLS blocked adapter 未参与运行。
- 没有做 minimization。
- 没有做 repeated reproduction。
