# slot mapping plan

- pkcs_container_parsing.openssl.family_adapter_recipe_v1: target=openssl, selected_units=21, glm_later=True
- asn1_nested_boundary.openssl.family_adapter_recipe_v1: target=openssl, selected_units=11, glm_later=True
- asn1_nested_boundary.mbedtls.family_adapter_recipe_v1: target=mbedtls, selected_units=11, glm_later=True

GLM 后续只能填 `slot_bindings`，不能自由生成 C。
