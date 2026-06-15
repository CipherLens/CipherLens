# x509 App-Level Seed Recovery Input Summary

- 进入 seed recovery 的原因：上一轮 7 个 C-path seed 均无 real original input / strict reproduction。
- 当前不能直接 minimal reproducer：没有 original_seed_found；placeholder/synthetic 不足以支撑 strict reproduction。
- placeholder/synthetic 不能冒充 real input：它们可能改变 issue 语义、版本依赖和 expected output。
- priority seeds: `['OPENSSL-ISSUE-14457', 'OPENSSL-ISSUE-29418', 'OPENSSL-ISSUE-14675']`
- low priority seeds: `['OPENSSL-ISSUE-11567', 'OPENSSL-ISSUE-11772', 'OPENSSL-ISSUE-23325', 'OPENSSL-ISSUE-6788']`
- render/run/GLM: `false`
