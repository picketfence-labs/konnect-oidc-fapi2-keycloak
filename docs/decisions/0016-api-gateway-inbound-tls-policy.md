# ADR 0016: API Gateway inbound TLSはmodern presetのTLS 1.3を使う

- Status: Proposed（Design ownerの方向合意。effective runtime metadataとhandshake証跡が揃うまで受入は未完了）
- Date: 2026-10-03
- Relates to: [ADR 0010](0010-api-gateway-resource-server-validation.md)、[ADR 0015](0015-api-resource-server-header-boundary.md)

## Context

API Gatewayのinbound TLSでは、Kong Gateway 3.16.0.0の`KONG_SSL_CIPHER_SUITE=modern` presetを使う。pinned imageのmodern presetはTLS 1.3のみを有効にし、TLS 1.2を要求するclientの拒否はcipher-suiteの選択より前のprotocol negotiationで起こり得る。Kongの`ssl_protocols`設定はcustom cipher suiteのときだけ有効になるため、見かけ上の設定値だけから実際のprotocol policyを推測しない。

FAPIのTLS最低要件はTLS 1.2以上であり、TLS 1.3のみのinbound listenerはその最低値を上回る。weak TLS 1.2 cipherを拒否するためにTLS 1.2を有効化したり、modern policyを弱めたりしない。inbound API listenerのTLS policyと、GatewayからKeycloak/Upstreamへのoutbound TLS policyは別々に記録する。この判断はFAPI全体への適合・認定を意味しない。

## Decision

1. API Gateway inboundは`modern` presetを維持する。Admin root configurationの要求値とeffective listener policyを別々に記録する。Adminのcipher presetが`modern`であることに加え、pinned Gateway image/architectureとOpenResty versionに束縛したbounded `nginx -T` dumpで、HTTP include graphとAPIの`0.0.0.0:8443 ssl` listenerへ適用される`ssl_protocols TLSv1.3`を確認した場合だけeffective policyを証明する。Adminの`ssl_protocols`が空でもeffective dumpが完全ならよいが、要求値を実効値の証拠に使わない。HTTPまたはAPI server scopeの`ssl_conf_command`はTLS設定を別途変え得るため、存在する場合はeffective policyを証明しない。
2. TLS 1.3のvalid mTLS controlでは、実際に交渉したprotocol versionと許可されたAEAD cipherを記録する。TLS 1.2のみをofferするclient controlと、TLS 1.2でweak suite `0x002F`をofferするclient negativeの両方について、ClientHelloにofferされたこと、peerによるprotocol-layer rejection、HTTP responseおよびUpstream到達がないこと、直後のTLS 1.3 positive controlを確認する。
3. `protocol_version` alertをcipher-suite固有の拒否理由として説明しない。TLS 1.2 client offersがprotocol policyで拒否されたことを示す場合に限ってTLS-RS-01のTLS version controlとして扱う。weak cipher単独の理由証明がない結果はfailまたはneeds-designのままにする。
4. TLS 1.1、SAN不一致、untrusted server CAは、それぞれ別のnegativeとpositive controlで扱う。API inbound policyの証跡をupstream TLSの証跡へ流用しない。

## Consequences

- Conformance文書はTLS 1.2が必ずnegotiateされるという受入条件を置かず、TLS 1.3-only API listenerのeffective policyとnegotiated strong cipherを検証する。
- この検証のため、隔離WP3 fixtureだけAdmin APIをcontainer loopbackに限定し、`KONG_ADMIN_GUI_LISTEN=off`とする。GUIが有効なpublic-generated config dumpには追加のGUI includeが現れ、固定した4ファイルinclude graphではeffective policyを証明できなかった。helperは未知includeを許容せず、通常Composeも変更しない。offline dumpの成功はfresh runtime acceptanceを意味しない。
- `nginx -T`のraw configはprocess memoryでのみ解析し、receiptにはpinned image/version、固定metadata、protocol enum、directive countだけを保存する。
- `ssl_conf_command`によるOpenSSL設定変更は固定parserがHTTP/API listener scopeで拒否し、未知TLS overrideからTLS 1.3-onlyを推論しない。
- 既存runtime receiptのweak-cipher failureはimmutableであり、このADRで遡及的にpassへ変更しない。新しいfixtureで上記すべての証拠が得られた場合だけ将来の結果を評価する。
- effective runtime configまたはhandshake evidenceが欠ける場合、TLS-RS-01をpassにしない。

## References

- [Kong Gateway SSL protocols and cipher suite configuration](https://developer.konghq.com/gateway/configuration/#ssl-protocols)
- [NGINX `ssl_conf_command` context and inheritance](https://nginx.org/en/docs/http/ngx_http_ssl_module.html#ssl_conf_command)
- [FAPI 2.0 Security Profile, section 5.2](https://openid.net/specs/fapi-security-profile-2_0-final.html)
