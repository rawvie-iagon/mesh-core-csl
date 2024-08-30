"use strict";
var __create = Object.create;
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __getProtoOf = Object.getPrototypeOf;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toESM = (mod, isNodeMode, target) => (target = mod != null ? __create(__getProtoOf(mod)) : {}, __copyProps(
  // If the importer is in node compatibility mode or this is not an ESM
  // file that has been converted to a CommonJS file using a Babel-
  // compatible transform (i.e. "__esModule" has not been set), then set
  // "default" to the CommonJS "module.exports" for node compatibility.
  isNodeMode || !mod || !mod.__esModule ? __defProp(target, "default", { value: mod, enumerable: true }) : target,
  mod
));
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

// src/index.ts
var src_exports = {};
__export(src_exports, {
  CSLSerializer: () => CSLSerializer,
  LANGUAGE_VERSIONS: () => LANGUAGE_VERSIONS,
  POLICY_ID_LENGTH: () => POLICY_ID_LENGTH,
  REDEEMER_TAGS: () => REDEEMER_TAGS,
  addrBech32ToHex: () => addrBech32ToHex,
  addrBech32ToObj: () => addrBech32ToObj,
  applyCborEncoding: () => applyCborEncoding,
  applyParamsToScript: () => applyParamsToScript,
  baseAddressToStakeAddress: () => baseAddressToStakeAddress,
  baseCertToObj: () => baseCertToObj,
  builderDataToCbor: () => builderDataToCbor,
  calculateTxHash: () => calculateTxHash,
  castDataToPlutusData: () => castDataToPlutusData,
  castRawDataToJsonString: () => castRawDataToJsonString,
  certificateToObj: () => certificateToObj,
  collateralTxInToObj: () => collateralTxInToObj,
  csl: () => csl,
  deserializeAddress: () => deserializeAddress,
  deserializeBech32Address: () => deserializeBech32Address,
  deserializeBip32PrivateKey: () => deserializeBip32PrivateKey,
  deserializeDataHash: () => deserializeDataHash,
  deserializeEd25519KeyHash: () => deserializeEd25519KeyHash,
  deserializeEd25519Signature: () => deserializeEd25519Signature,
  deserializeNativeScript: () => deserializeNativeScript,
  deserializePlutusData: () => deserializePlutusData,
  deserializePlutusScript: () => deserializePlutusScript,
  deserializePublicKey: () => deserializePublicKey,
  deserializeScriptHash: () => deserializeScriptHash,
  deserializeScriptRef: () => deserializeScriptRef,
  deserializeTx: () => deserializeTx,
  deserializeTxBody: () => deserializeTxBody,
  deserializeTxHash: () => deserializeTxHash,
  deserializeTxUnspentOutput: () => deserializeTxUnspentOutput,
  deserializeTxWitnessSet: () => deserializeTxWitnessSet,
  deserializeValue: () => deserializeValue,
  fromBytes: () => fromBytes,
  fromLovelace: () => fromLovelace,
  fromUTF8: () => fromUTF8,
  getV2ScriptHash: () => getV2ScriptHash,
  keyHashToRewardAddress: () => keyHashToRewardAddress,
  meshTxBuilderBodyToObj: () => meshTxBuilderBodyToObj,
  mintItemToObj: () => mintItemToObj,
  mintParametersObj: () => mintParametersObj,
  nativeMintItemToObj: () => nativeMintItemToObj,
  outputToObj: () => outputToObj,
  parseDatumCbor: () => parseDatumCbor,
  parseInlineDatum: () => parseInlineDatum,
  plutusMintItemToObj: () => plutusMintItemToObj,
  poolIdBech32ToHex: () => poolIdBech32ToHex,
  poolIdHexToBech32: () => poolIdHexToBech32,
  poolMetadataToObj: () => poolMetadataToObj,
  poolParamsToObj: () => poolParamsToObj,
  redeemerToObj: () => redeemerToObj,
  relayToObj: () => relayToObj,
  resolveDataHash: () => resolveDataHash,
  resolveEd25519KeyHash: () => resolveEd25519KeyHash,
  resolveNativeScriptAddress: () => resolveNativeScriptAddress,
  resolveNativeScriptHash: () => resolveNativeScriptHash,
  resolveNativeScriptHex: () => resolveNativeScriptHex,
  resolvePlutusScriptAddress: () => resolvePlutusScriptAddress,
  resolvePrivateKey: () => resolvePrivateKey,
  resolveRewardAddress: () => resolveRewardAddress,
  resolveScriptRef: () => resolveScriptRef,
  resolveStakeKeyHash: () => resolveStakeKeyHash,
  rewardAddressToKeyHash: () => rewardAddressToKeyHash,
  scriptHashToBech32: () => scriptHashToBech32,
  scriptHashToRewardAddress: () => scriptHashToRewardAddress,
  scriptSourceToObj: () => scriptSourceToObj,
  scriptTxInParameterToObj: () => scriptTxInParameterToObj,
  serializeAddressObj: () => serializeAddressObj,
  serializePlutusAddressToBech32: () => serializePlutusAddressToBech32,
  serializePoolId: () => serializePoolId,
  serialzeAddress: () => serialzeAddress,
  signTransaction: () => signTransaction,
  simpleScriptSourceToObj: () => simpleScriptSourceToObj,
  skeyToPubKeyHash: () => skeyToPubKeyHash,
  toAddress: () => toAddress,
  toBaseAddress: () => toBaseAddress,
  toBytes: () => toBytes,
  toEnterpriseAddress: () => toEnterpriseAddress,
  toLovelace: () => toLovelace,
  toNativeScript: () => toNativeScript,
  toPlutusData: () => toPlutusData,
  toRewardAddress: () => toRewardAddress,
  toScriptRef: () => toScriptRef,
  toUTF8: () => toUTF8,
  txInParameterToObj: () => txInParameterToObj,
  txInToObj: () => txInToObj,
  utxoToObj: () => utxoToObj,
  v2ScriptToBech32: () => v2ScriptToBech32,
  withdrawalToObj: () => withdrawalToObj
});
module.exports = __toCommonJS(src_exports);

// src/utils/address.ts
var import_common2 = require("@meshsdk/common");

// src/deser/csl.ts
var csl = __toESM(require("@sidan-lab/sidan-csl-rs-nodejs"), 1);

// src/deser/constants.ts
var LANGUAGE_VERSIONS = {
  V1: csl.Language.new_plutus_v1(),
  V2: csl.Language.new_plutus_v2(),
  V3: csl.Language.new_plutus_v3()
};
var REDEEMER_TAGS = {
  CERT: csl.RedeemerTag.new_cert(),
  MINT: csl.RedeemerTag.new_mint(),
  REWARD: csl.RedeemerTag.new_reward(),
  SPEND: csl.RedeemerTag.new_spend()
};
var POLICY_ID_LENGTH = 56;

// src/deser/converter.ts
var import_json_bigint = __toESM(require("json-bigint"), 1);
var toAddress = (bech32) => csl.Address.from_bech32(bech32);
var toBaseAddress = (bech32) => csl.BaseAddress.from_address(toAddress(bech32));
var toEnterpriseAddress = (bech32) => csl.EnterpriseAddress.from_address(toAddress(bech32));
var toRewardAddress = (bech32) => csl.RewardAddress.from_address(toAddress(bech32));
var fromBytes = (bytes) => Buffer.from(bytes).toString("hex");
var toBytes = (hex) => {
  if (hex.length % 2 === 0 && /^[0-9A-F]*$/i.test(hex))
    return Buffer.from(hex, "hex");
  return Buffer.from(hex, "utf-8");
};
var fromUTF8 = (utf8) => {
  if (utf8.length % 2 === 0 && /^[0-9A-F]*$/i.test(utf8)) return utf8;
  return fromBytes(Buffer.from(utf8, "utf-8"));
};
var toUTF8 = (hex) => Buffer.from(hex, "hex").toString("utf-8");
var fromLovelace = (lovelace) => lovelace / 1e6;
var toLovelace = (ada) => ada * 1e6;
var toScriptRef = (script) => {
  if ("code" in script) {
    const plutusScript = deserializePlutusScript(script.code, script.version);
    return csl.ScriptRef.new_plutus_script(plutusScript);
  }
  return csl.ScriptRef.new_native_script(toNativeScript(script));
};
var toPlutusData = (data) => {
  const toPlutusList = (dataArray) => {
    const plutusList = csl.PlutusList.new();
    dataArray.forEach((element) => {
      plutusList.add(toPlutusData(element));
    });
    return plutusList;
  };
  switch (typeof data) {
    case "string":
      return csl.PlutusData.new_bytes(toBytes(data));
    case "number":
      return csl.PlutusData.new_integer(csl.BigInt.from_str(data.toString()));
    case "bigint":
      return csl.PlutusData.new_integer(csl.BigInt.from_str(data.toString()));
    case "object":
      if (data instanceof Array) {
        const plutusList = toPlutusList(data);
        return csl.PlutusData.new_list(plutusList);
      }
      if (data instanceof Map) {
        const plutusMap = csl.PlutusMap.new();
        data.forEach((value, key) => {
          const plutusMapValue = csl.PlutusMapValues.new();
          plutusMapValue.add(toPlutusData(value));
          plutusMap.insert(toPlutusData(key), plutusMapValue);
        });
        return csl.PlutusData.new_map(plutusMap);
      }
      return csl.PlutusData.new_constr_plutus_data(
        csl.ConstrPlutusData.new(
          csl.BigNum.from_str(data.alternative.toString()),
          toPlutusList(data.fields)
        )
      );
  }
};
var castRawDataToJsonString = (rawData) => {
  if (typeof rawData === "object") {
    return import_json_bigint.default.stringify(rawData);
  }
  return rawData;
};
var castDataToPlutusData = ({
  type,
  content
}) => {
  if (type === "Mesh") {
    return toPlutusData(content);
  }
  if (type === "CBOR") {
    return csl.PlutusData.from_hex(content);
  }
  return csl.PlutusData.from_json(
    content,
    csl.PlutusDatumSchema.DetailedSchema
  );
};
var toNativeScript = (script) => {
  const toNativeScripts = (scripts) => {
    const nativeScripts = csl.NativeScripts.new();
    scripts.forEach((script2) => {
      nativeScripts.add(toNativeScript(script2));
    });
    return nativeScripts;
  };
  switch (script.type) {
    case "all":
      return csl.NativeScript.new_script_all(
        csl.ScriptAll.new(toNativeScripts(script.scripts))
      );
    case "any":
      return csl.NativeScript.new_script_any(
        csl.ScriptAny.new(toNativeScripts(script.scripts))
      );
    case "atLeast":
      return csl.NativeScript.new_script_n_of_k(
        csl.ScriptNOfK.new(script.required, toNativeScripts(script.scripts))
      );
    case "after":
      return csl.NativeScript.new_timelock_start(
        csl.TimelockStart.new_timelockstart(csl.BigNum.from_str(script.slot))
      );
    case "before":
      return csl.NativeScript.new_timelock_expiry(
        csl.TimelockExpiry.new_timelockexpiry(csl.BigNum.from_str(script.slot))
      );
    case "sig":
      return csl.NativeScript.new_script_pubkey(
        csl.ScriptPubkey.new(deserializeEd25519KeyHash(script.keyHash))
      );
  }
};

// src/deser/deserializer.ts
var deserializeAddress = (address) => csl.Address.from_bytes(toBytes(address));
var deserializeBip32PrivateKey = (bip32PrivateKey) => csl.Bip32PrivateKey.from_bytes(toBytes(bip32PrivateKey));
var deserializeDataHash = (dataHash) => csl.DataHash.from_bytes(toBytes(dataHash));
var deserializeEd25519KeyHash = (ed25519KeyHash) => csl.Ed25519KeyHash.from_bytes(toBytes(ed25519KeyHash));
var deserializeEd25519Signature = (ed25519Signature) => csl.Ed25519Signature.from_bytes(toBytes(ed25519Signature));
var deserializeNativeScript = (nativeScript) => csl.NativeScript.from_bytes(toBytes(nativeScript));
var deserializePublicKey = (publicKey) => csl.PublicKey.from_bytes(toBytes(publicKey));
var deserializePlutusData = (plutusData) => csl.PlutusData.from_bytes(toBytes(plutusData));
var deserializePlutusScript = (plutusScript, version) => csl.PlutusScript.from_hex_with_version(
  plutusScript,
  LANGUAGE_VERSIONS[version]
);
var deserializeScriptRef = (scriptRef) => csl.ScriptRef.from_bytes(toBytes(scriptRef));
var deserializeScriptHash = (scriptHash) => csl.ScriptHash.from_bytes(toBytes(scriptHash));
var deserializeTx = (tx) => csl.Transaction.from_bytes(toBytes(tx));
var deserializeTxBody = (txBody) => csl.TransactionBody.from_bytes(toBytes(txBody));
var deserializeTxHash = (txHash) => csl.TransactionHash.from_bytes(toBytes(txHash));
var deserializeTxUnspentOutput = (txUnspentOutput) => csl.TransactionUnspentOutput.from_bytes(toBytes(txUnspentOutput));
var deserializeTxWitnessSet = (txWitnessSet) => csl.TransactionWitnessSet.from_bytes(toBytes(txWitnessSet));
var deserializeValue = (value) => csl.Value.from_bytes(toBytes(value));

// src/deser/resolver.ts
var import_common = require("@meshsdk/common");
var resolveStakeKeyHash = (bech32) => {
  try {
    const stakeKeyHash = [
      toBaseAddress(bech32)?.stake_cred().to_keyhash(),
      toRewardAddress(bech32)?.payment_cred().to_keyhash()
    ].find((kh) => kh !== void 0);
    if (stakeKeyHash !== void 0) return stakeKeyHash.to_hex();
    throw new Error(`Couldn't resolve stake key hash from address: ${bech32}`);
  } catch (error) {
    throw new Error(`An error occurred during resolveStakeKeyHash: ${error}.`);
  }
};
var resolvePrivateKey = (words) => {
  const buildBip32PrivateKey = (entropy2, password = "") => {
    return csl.Bip32PrivateKey.from_bip39_entropy(
      toBytes(entropy2),
      toBytes(fromUTF8(password))
    );
  };
  const entropy = (0, import_common.mnemonicToEntropy)(words.join(" "));
  const bip32PrivateKey = buildBip32PrivateKey(entropy);
  const bech32PrivateKey = bip32PrivateKey.to_bech32();
  bip32PrivateKey.free();
  return bech32PrivateKey;
};
var resolveNativeScriptAddress = (script, networkId = 0) => {
  const nativeScript = toNativeScript(script);
  const enterpriseAddress = csl.EnterpriseAddress.new(
    networkId,
    csl.Credential.from_scripthash(nativeScript.hash())
  );
  return enterpriseAddress.to_address().to_bech32();
};
var resolvePlutusScriptAddress = (script, networkId = 0) => {
  const plutusScript = deserializePlutusScript(script.code, script.version);
  const enterpriseAddress = csl.EnterpriseAddress.new(
    networkId,
    csl.Credential.from_scripthash(plutusScript.hash())
  );
  return enterpriseAddress.to_address().to_bech32();
};
var resolveNativeScriptHash = (script) => {
  return toNativeScript(script).hash().to_hex();
};
var resolveRewardAddress = (bech32) => {
  const buildRewardAddress = (networkId, stakeKeyHash) => {
    return csl.RewardAddress.new(
      networkId,
      csl.Credential.from_keyhash(stakeKeyHash)
    );
  };
  try {
    const address = toAddress(bech32);
    const baseAddress = toBaseAddress(bech32);
    const stakeKeyHash = baseAddress?.stake_cred().to_keyhash();
    if (stakeKeyHash !== void 0)
      return buildRewardAddress(address.network_id(), stakeKeyHash).to_address().to_bech32();
    throw new Error(`Couldn't resolve reward address from address: ${bech32}`);
  } catch (error) {
    throw new Error(`An error occurred during resolveRewardAddress: ${error}.`);
  }
};
var resolveDataHash = (data) => {
  const plutusData = toPlutusData(data);
  const dataHash = csl.hash_plutus_data(plutusData);
  return dataHash.to_hex();
};
var resolveNativeScriptHex = (script) => {
  return toNativeScript(script).to_hex();
};
var serializePoolId = (hash) => {
  return csl.Ed25519KeyHash.from_hex(hash).to_bech32("pool1");
};
var resolveScriptRef = (script) => {
  return toScriptRef(script).to_hex();
};
var resolveEd25519KeyHash = (bech32) => {
  return csl.Ed25519KeyHash.from_bech32(bech32).to_hex();
};

// src/utils/scripts.ts
var getV2ScriptHash = (script) => csl.get_v2_script_hash(script);

// src/utils/address.ts
var serialzeAddress = (deserializedAddress, networkId = 0) => {
  const {
    pubKeyHash,
    scriptHash,
    stakeCredentialHash,
    stakeScriptCredentialHash
  } = deserializedAddress;
  const isPaymentScript = !pubKeyHash;
  const isStakeScript = !stakeCredentialHash;
  const paymentHash = isPaymentScript ? scriptHash : pubKeyHash;
  const stakeHash = isStakeScript ? stakeScriptCredentialHash : stakeCredentialHash;
  if (!paymentHash)
    throw new Error(
      "Error: serializeAddress: Address must contain a payment part"
    );
  const addressObj = isPaymentScript ? (0, import_common2.pubKeyAddress)(paymentHash, stakeHash, isStakeScript) : (0, import_common2.scriptAddress)(paymentHash, stakeHash, isStakeScript);
  return serializeAddressObj(addressObj, networkId);
};
var addrBech32ToHex = (bech32) => {
  const hexAddress = csl.Address.from_bech32(bech32).to_hex();
  const cslAddress = csl.Address.from_hex(hexAddress);
  const hex = csl.PlutusData.from_address(cslAddress).to_hex();
  return hex;
};
var addrBech32ToObj = (bech32) => {
  const hexAddress = csl.Address.from_bech32(bech32).to_hex();
  const cslAddress = csl.Address.from_hex(hexAddress);
  const json = JSON.parse(csl.PlutusData.from_address(cslAddress).to_json(1));
  return json;
};
var serializeAddressObj = (plutusDataAddressObject, networkId = 0) => {
  const bech32Addr = csl.parse_plutus_address_obj_to_bech32(
    JSON.stringify(plutusDataAddressObject),
    networkId
  );
  return bech32Addr;
};
var serializePlutusAddressToBech32 = (plutusHex, networkId = 0) => {
  const cslPlutusDataAddress = csl.PlutusData.from_hex(plutusHex);
  const plutusDataAddressObject = JSON.parse(
    cslPlutusDataAddress.to_json(csl.PlutusDatumSchema.DetailedSchema)
  );
  return serializeAddressObj(plutusDataAddressObject, networkId);
};
var deserializeBech32Address = (bech32Addr) => {
  const deserializedAddress = csl.deserialize_bech32_address(bech32Addr);
  return {
    pubKeyHash: deserializedAddress.get_pub_key_hash(),
    scriptHash: deserializedAddress.get_script_hash(),
    stakeCredentialHash: deserializedAddress.get_stake_key_hash(),
    stakeScriptCredentialHash: deserializedAddress.get_stake_key_script_hash()
  };
};
var scriptHashToBech32 = (scriptHash, stakeCredentialHash, networkId = 0, isScriptStakeCredentialHash = false) => csl.wasm_script_to_address(
  networkId,
  scriptHash,
  stakeCredentialHash,
  isScriptStakeCredentialHash
);
var v2ScriptToBech32 = (scriptCbor, stakeCredential, networkId = 0, isScriptStakeCredential = false) => scriptHashToBech32(
  getV2ScriptHash(scriptCbor),
  stakeCredential,
  networkId,
  isScriptStakeCredential
);

// src/utils/datum.ts
var parseInlineDatum = (utxo) => {
  const datumCbor = utxo.inline_datum || "";
  const parsedDatum = csl.PlutusData.from_hex(datumCbor);
  const datum = JSON.parse(parsedDatum.to_json(1));
  return datum;
};
var parseDatumCbor = (datumCbor) => {
  const parsedDatum = csl.PlutusData.from_hex(datumCbor);
  const datum = JSON.parse(parsedDatum.to_json(1));
  return datum;
};

// src/utils/credentials.ts
var skeyToPubKeyHash = (skeyHex) => {
  const isHexUnclean = skeyHex.slice(0, 4) === "5820" && skeyHex.length === 68;
  const cleanHex = isHexUnclean ? skeyHex.slice(4) : skeyHex;
  return csl.PrivateKey.from_hex(cleanHex).to_public().hash().to_hex();
};

// src/utils/staking.ts
var poolIdHexToBech32 = (poolIdHash) => {
  const cslPoolIdHash = csl.Ed25519KeyHash.from_hex(poolIdHash);
  return cslPoolIdHash.to_bech32("pool");
};
var poolIdBech32ToHex = (poolIdBech32) => {
  const cslPoolIdHash = csl.Ed25519KeyHash.from_bech32(poolIdBech32);
  return Buffer.from(cslPoolIdHash.to_bytes()).toString("hex");
};
var baseAddressToStakeAddress = (baseAddressBech32, network = 1) => {
  const networkId = network === 1 ? csl.NetworkId.mainnet().kind() : csl.NetworkId.testnet().kind();
  const stakeCred = csl.BaseAddress.from_address(
    csl.Address.from_bech32(baseAddressBech32)
  )?.stake_cred();
  if (stakeCred) {
    const stakeAddress = csl.RewardAddress.new(networkId, stakeCred).to_address().to_bech32();
    return stakeAddress;
  }
  return "";
};
var rewardAddressToKeyHash = (rewardBech32) => {
  return toRewardAddress(rewardBech32)?.payment_cred().to_keyhash()?.to_hex();
};
var scriptHashToRewardAddress = (scriptHashHex, network = 1) => {
  const networkId = network === 1 ? csl.NetworkId.mainnet().kind() : csl.NetworkId.testnet().kind();
  const scriptHash = csl.ScriptHash.from_hex(scriptHashHex);
  const credential = csl.Credential.from_scripthash(scriptHash);
  const rewardAddress = csl.RewardAddress.new(networkId, credential).to_address().to_bech32();
  return rewardAddress;
};
var keyHashToRewardAddress = (keyHashHex, network = 1) => {
  const networkId = network === 1 ? csl.NetworkId.mainnet().kind() : csl.NetworkId.testnet().kind();
  const keyHash = csl.Ed25519KeyHash.from_hex(keyHashHex);
  const credential = csl.Credential.from_scripthash(keyHash);
  const rewardAddress = csl.RewardAddress.new(networkId, credential).to_address().to_bech32();
  return rewardAddress;
};

// src/wasm.ts
var parseWasmResult = (result) => {
  if (result.get_status() !== "success") {
    throw new Error(result.get_data());
  }
  return result.get_data();
};

// src/utils/transaction.ts
var calculateTxHash = (txHex) => {
  const result = csl.js_calculate_tx_hash(txHex);
  return parseWasmResult(result);
};
var signTransaction = (txHex, signingKeys) => {
  const cslSigningKeys = csl.JsVecString.new();
  signingKeys.forEach((key) => {
    cslSigningKeys.add(key);
  });
  const result = csl.js_sign_transaction(txHex, cslSigningKeys);
  return parseWasmResult(result);
};

// src/utils/aiken.ts
var applyParamsToScript = (rawScript, params, type = "Mesh") => {
  const cslParams = csl.JsVecString.new();
  let paramType = csl.BuilderDataType.CBOR;
  switch (type) {
    case "JSON":
      paramType = csl.BuilderDataType.JSON;
      params.forEach((param) => {
        if (typeof param === "object") {
          cslParams.add(JSON.stringify(param));
        } else if (typeof param === "string") {
          cslParams.add(param);
        }
      });
      break;
    case "Mesh":
      params.forEach((param) => {
        const paramCbor = toPlutusData(param);
        cslParams.add(paramCbor.to_hex());
      });
      break;
    default:
      params.forEach((param) => {
        cslParams.add(param);
      });
      break;
  }
  return csl.js_apply_params_to_script(rawScript, cslParams, paramType);
};
var applyCborEncoding = (rawScript) => {
  return csl.js_apply_params_to_script(
    rawScript,
    csl.JsVecString.new(),
    csl.BuilderDataType.CBOR
  );
};

// src/core/serializer.ts
var import_json_bigint2 = __toESM(require("json-bigint"), 1);
var import_common4 = require("@meshsdk/common");

// src/core/adaptor/index.ts
var import_common3 = require("@meshsdk/common");

// src/core/adaptor/data.ts
var builderDataToCbor = ({ type, content }) => {
  if (type === "Mesh") {
    return toPlutusData(content).to_hex();
  }
  if (type === "CBOR") {
    return csl.PlutusData.from_hex(content).to_hex();
  }
  return csl.PlutusData.from_json(
    content,
    csl.PlutusDatumSchema.DetailedSchema
  ).to_hex();
};
var redeemerToObj = (redeemer) => {
  return {
    data: builderDataToCbor(redeemer.data),
    exUnits: redeemer.exUnits
  };
};

// src/core/adaptor/script.ts
var scriptSourceToObj = (scriptSource) => {
  if (scriptSource.type === "Provided") {
    return {
      providedScriptSource: {
        scriptCbor: scriptSource.script.code,
        languageVersion: scriptSource.script.version.toLocaleLowerCase()
      }
    };
  }
  return {
    inlineScriptSource: {
      refTxIn: {
        txHash: scriptSource.txHash,
        txIndex: scriptSource.txIndex
      },
      scriptHash: scriptSource.scriptHash ?? "",
      languageVersion: scriptSource.version.toLocaleLowerCase(),
      scriptSize: BigInt(scriptSource.scriptSize ?? "0")
    }
  };
};
var simpleScriptSourceToObj = (scriptSource) => {
  if (scriptSource.type === "Provided") {
    return {
      providedSimpleScriptSource: {
        scriptCbor: scriptSource.scriptCode
      }
    };
  }
  return {
    inlineSimpleScriptSource: {
      refTxIn: {
        txHash: scriptSource.txHash,
        txIndex: scriptSource.txIndex
      },
      simpleScriptHash: scriptSource.simpleScriptHash ?? ""
    }
  };
};

// src/core/adaptor/certificate.ts
var certificateToObj = (certificate) => {
  const baseCert = certificate.certType;
  switch (certificate.type) {
    case "BasicCertificate":
      return {
        basicCertificate: baseCertToObj(baseCert)
      };
    case "ScriptCertificate":
      return {
        scriptCertificate: {
          cert: baseCertToObj(baseCert),
          redeemer: certificate.redeemer ? redeemerToObj(certificate.redeemer) : null,
          scriptSource: certificate.scriptSource ? scriptSourceToObj(certificate.scriptSource) : null
        }
      };
    case "SimpleScriptCertificate":
      return {
        simpleScriptCertificate: {
          cert: baseCertToObj(baseCert),
          simpleScriptSource: certificate.simpleScriptSource ? simpleScriptSourceToObj(certificate.simpleScriptSource) : null
        }
      };
  }
};
var baseCertToObj = (baseCert) => {
  switch (baseCert.type) {
    case "RegisterPool":
      return {
        registerPool: {
          poolParams: poolParamsToObj(baseCert.poolParams)
        }
      };
    case "RegisterStake":
      return {
        registerStake: {
          stakeKeyAddress: baseCert.stakeKeyAddress,
          coin: 2e6
          // TODO: change in conway era
        }
      };
    case "DelegateStake":
      return {
        delegateStake: {
          stakeKeyAddress: baseCert.stakeKeyAddress,
          poolId: baseCert.poolId
        }
      };
    case "DeregisterStake":
      return {
        deregisterStake: {
          stakeKeyAddress: baseCert.stakeKeyAddress
        }
      };
    case "RetirePool":
      return {
        retirePool: {
          poolId: baseCert.poolId,
          epoch: baseCert.epoch
        }
      };
    case "VoteDelegation":
      return {
        voteDelegation: {
          stakeKeyAddress: baseCert.stakeKeyAddress,
          drep: baseCert.drep
        }
      };
    case "StakeAndVoteDelegation":
      return {
        stakeAndVoteDelegation: {
          stakeKeyAddress: baseCert.stakeKeyAddress,
          poolKeyHash: baseCert.poolKeyHash,
          drep: baseCert.drep
        }
      };
    case "StakeRegistrationAndDelegation":
      return {
        stakeRegistrationAndDelegation: {
          stakeKeyAddress: baseCert.stakeKeyAddress,
          poolKeyHash: baseCert.poolKeyHash,
          coin: baseCert.coin
        }
      };
    case "VoteRegistrationAndDelegation":
      return {
        voteRegistrationAndDelegation: {
          stakeKeyAddress: baseCert.stakeKeyAddress,
          drep: baseCert.drep,
          coin: baseCert.coin
        }
      };
    case "StakeVoteRegistrationAndDelegation":
      return {
        stakeVoteRegistrationAndDelegation: {
          stakeKeyAddress: baseCert.stakeKeyAddress,
          poolKeyHash: baseCert.poolKeyHash,
          drep: baseCert.drep,
          coin: baseCert.coin
        }
      };
    case "CommitteeHotAuth":
      return {
        committeeHotAuth: {
          committeeColdKeyAddress: baseCert.committeeColdKeyAddress,
          committeeHotKeyAddress: baseCert.committeeHotKeyAddress
        }
      };
    case "CommitteeColdResign":
      return {
        committeeColdResign: {
          committeeColdKeyAddress: baseCert.committeeColdKeyAddress,
          anchor: baseCert.anchor ?? null
        }
      };
    case "DRepRegistration":
      return {
        dRepRegistration: {
          votingKeyAddress: baseCert.votingKeyAddress,
          coin: baseCert.coin,
          anchor: baseCert.anchor ?? null
        }
      };
    case "DRepDeregistration":
      return {
        dRepDeregistration: {
          votingKeyAddress: baseCert.votingKeyAddress,
          coin: baseCert.coin
        }
      };
    case "DRepUpdate":
      return {
        dRepUpdate: {
          votingKeyAddress: baseCert.votingKeyAddress,
          anchor: baseCert.anchor
        }
      };
  }
};
var poolParamsToObj = (poolParams) => {
  return {
    vrfKeyHash: poolParams.vrfKeyHash,
    operator: poolParams.operator,
    pledge: poolParams.pledge,
    cost: poolParams.cost,
    margin: poolParams.margin,
    relays: poolParams.relays.map((relay) => relayToObj(relay)),
    owners: poolParams.owners,
    rewardAddress: poolParams.rewardAddress,
    metadata: poolParams.metadata ? poolMetadataToObj(poolParams.metadata) : void 0
  };
};
var poolMetadataToObj = (poolMetadata) => {
  return {
    url: poolMetadata.URL,
    metadata: poolMetadata.hash
  };
};
var relayToObj = (relay) => {
  switch (relay.type) {
    case "SingleHostAddr":
      return {
        singleHostAddr: {
          ipv4: relay.IPV4,
          ipv6: relay.IPV6,
          port: relay.port
        }
      };
    case "SingleHostName":
      return {
        singleHostName: {
          hostname: relay.domainName,
          port: relay.port
        }
      };
    case "MultiHostName":
      return {
        multiHostName: {
          dnsName: relay.domainName
        }
      };
  }
};

// src/core/adaptor/mint.ts
var mintItemToObj = (mintItem) => {
  switch (mintItem.type) {
    case "Plutus":
      return {
        scriptMint: plutusMintItemToObj(mintItem)
      };
    case "Native":
      return {
        simpleScriptMint: nativeMintItemToObj(
          mintItem
        )
      };
  }
};
var plutusMintItemToObj = (mintItem) => {
  let scriptSource = scriptSourceToObj(
    mintItem.scriptSource
  );
  return {
    mint: mintParametersObj(mintItem),
    redeemer: mintItem.redeemer ? redeemerToObj(mintItem.redeemer) : null,
    scriptSource
  };
};
var nativeMintItemToObj = (mintItem) => {
  return {
    mint: mintParametersObj(mintItem),
    scriptSource: simpleScriptSourceToObj(
      mintItem.scriptSource
    )
  };
};
var mintParametersObj = (mintItem) => {
  return {
    policyId: mintItem.policyId,
    assetName: mintItem.assetName,
    amount: BigInt(mintItem.amount)
  };
};

// src/core/adaptor/output.ts
var outputToObj = (output) => {
  let datum = null;
  if (output.datum) {
    switch (output.datum.type) {
      case "Inline":
        datum = { inline: builderDataToCbor(output.datum.data) };
        break;
      case "Hash":
        datum = { hash: builderDataToCbor(output.datum.data) };
        break;
      case "Embedded":
        datum = { embedded: builderDataToCbor(output.datum.data) };
        break;
    }
  }
  const refScript = output.referenceScript;
  return {
    address: output.address,
    amount: output.amount,
    datum,
    referenceScript: output.referenceScript ? {
      providedScriptSource: {
        scriptCbor: refScript.code,
        languageVersion: refScript.version.toLocaleLowerCase()
      }
    } : null
  };
};

// src/core/adaptor/txIn.ts
var txInToObj = (txIn) => {
  switch (txIn.type) {
    case "PubKey":
      return {
        pubKeyTxIn: {
          txIn: txInParameterToObj(txIn.txIn)
        }
      };
    case "Script":
      return {
        scriptTxIn: {
          txIn: txInParameterToObj(txIn.txIn),
          scriptTxIn: scriptTxInParameterToObj(txIn.scriptTxIn)
        }
      };
    case "SimpleScript":
      return {};
  }
};
var collateralTxInToObj = (txIn) => {
  return {
    txIn: txInParameterToObj(txIn.txIn)
  };
};
var txInParameterToObj = (txInParameter) => {
  return {
    txHash: txInParameter.txHash,
    txIndex: txInParameter.txIndex,
    amount: txInParameter.amount ?? null,
    address: txInParameter.address ?? null
  };
};
var scriptTxInParameterToObj = (scriptTxInParameter) => {
  let scriptSource = null;
  let datumSource = null;
  if (scriptTxInParameter.scriptSource) {
    scriptSource = scriptSourceToObj(scriptTxInParameter.scriptSource);
  }
  if (scriptTxInParameter.datumSource) {
    switch (scriptTxInParameter.datumSource.type) {
      case "Provided":
        datumSource = {
          providedDatumSource: {
            data: builderDataToCbor(scriptTxInParameter.datumSource.data)
          }
        };
        break;
      case "Inline":
        datumSource = {
          inlineDatumSource: {
            txHash: scriptTxInParameter.datumSource.txHash,
            txIndex: scriptTxInParameter.datumSource.txIndex
          }
        };
        break;
    }
  }
  return {
    scriptSource,
    datumSource,
    redeemer: scriptTxInParameter.redeemer ? redeemerToObj(scriptTxInParameter.redeemer) : null
  };
};

// src/core/adaptor/withdrawal.ts
var withdrawalToObj = (withdrawal) => {
  if (withdrawal.type === "PubKeyWithdrawal") {
    return {
      pubKeyWithdrawal: {
        address: withdrawal.address,
        coin: BigInt(withdrawal.coin)
      }
    };
  } else if (withdrawal.type === "ScriptWithdrawal") {
    if (!withdrawal.scriptSource) {
      throw new Error(
        "withdrawalToObj: missing scriptSource in plutusScriptWithdrawal."
      );
    }
    if (!withdrawal.redeemer) {
      throw new Error(
        "withdrawalToObj: missing redeemer in plutusScriptWithdrawal."
      );
    }
    return {
      plutusScriptWithdrawal: {
        address: withdrawal.address,
        coin: BigInt(withdrawal.coin),
        scriptSource: scriptSourceToObj(withdrawal.scriptSource),
        redeemer: redeemerToObj(withdrawal.redeemer)
      }
    };
  } else {
    if (!withdrawal.scriptSource) {
      throw new Error(
        "withdrawalToObj: missing script source in simpleScriptWithdrawal"
      );
    }
    return {
      simpleScriptWithdrawal: {
        address: withdrawal.address,
        coin: BigInt(withdrawal.coin),
        scriptSource: simpleScriptSourceToObj(withdrawal.scriptSource)
      }
    };
  }
};

// src/core/adaptor/utxo.ts
var utxoToObj = ({
  input: { outputIndex, txHash },
  output: { address, amount, dataHash, plutusData, scriptRef, scriptHash }
}) => {
  return {
    input: {
      outputIndex,
      txHash
    },
    output: {
      address,
      amount,
      dataHash: dataHash ?? null,
      plutusData: plutusData ?? null,
      scriptRef: scriptRef ?? null,
      scriptHash: scriptHash ?? null
    }
  };
};

// src/core/adaptor/index.ts
var meshTxBuilderBodyToObj = ({
  inputs,
  outputs,
  collaterals,
  requiredSignatures,
  referenceInputs,
  mints,
  changeAddress,
  metadata,
  validityRange,
  certificates,
  signingKey,
  withdrawals,
  network
}) => {
  return {
    inputs: inputs.map(txInToObj),
    outputs: outputs.map(outputToObj),
    collaterals: collaterals.map(collateralTxInToObj),
    requiredSignatures,
    referenceInputs,
    mints: mints.map((mint) => mintItemToObj(mint)),
    changeAddress,
    metadata,
    validityRange: (0, import_common3.validityRangeToObj)(validityRange),
    certificates: certificates.map(certificateToObj),
    signingKey,
    withdrawals: withdrawals.map(withdrawalToObj),
    network
  };
};

// src/core/serializer.ts
var CSLSerializer = class {
  /**
   * Set to true to enable verbose logging for the txBodyJson prior going into build
   */
  verbose;
  protocolParams;
  meshTxBuilderBody = (0, import_common4.emptyTxBuilderBody)();
  constructor(protocolParams, verbose = false) {
    this.protocolParams = protocolParams || import_common4.DEFAULT_PROTOCOL_PARAMETERS;
    this.verbose = verbose;
  }
  serializeTxBody(txBody, protocolParams) {
    const txBodyJson = import_json_bigint2.default.stringify(meshTxBuilderBodyToObj(txBody));
    const params = import_json_bigint2.default.stringify(protocolParams || this.protocolParams);
    if (this.verbose) {
      console.log("txBodyJson", txBodyJson);
    }
    const txBuildResult = csl.js_serialize_tx_body(txBodyJson, params);
    if (txBuildResult.get_status() !== "success") {
      throw new Error(`txBuildResult error: ${txBuildResult.get_data()}`);
    }
    return txBuildResult.get_data();
  }
  addSigningKeys(txHex, signingKeys) {
    if (signingKeys.length > 0) {
      return signTransaction(txHex, signingKeys);
    }
    return txHex;
  }
  serializeData(data) {
    return builderDataToCbor(data);
  }
  serializeAddress(address, networkId) {
    return serialzeAddress(address, networkId);
  }
  serializePoolId(hash) {
    return serializePoolId(hash);
  }
  serializeRewardAddress(stakeKeyHash, isScriptHash, network_id) {
    return isScriptHash ? scriptHashToRewardAddress(stakeKeyHash, network_id) : keyHashToRewardAddress(stakeKeyHash, network_id);
  }
  deserializer = {
    key: {
      deserializeAddress: function(bech32) {
        return deserializeBech32Address(bech32);
      }
    },
    script: {
      deserializeNativeScript: function(script) {
        const nativeScript = toNativeScript(script);
        const scriptCbor = nativeScript.to_hex();
        const scriptHash = nativeScript.hash().to_hex();
        return {
          scriptHash,
          scriptCbor
        };
      },
      deserializePlutusScript: function(script) {
        const scriptHash = deserializePlutusScript(script.code, script.version).hash().to_hex();
        return { scriptHash, scriptCbor: script.code };
      }
    },
    cert: {
      deserializePoolId: function(poolId) {
        return resolveEd25519KeyHash(poolId);
      }
    }
  };
  resolver = {
    keys: {
      resolveStakeKeyHash: function(bech32) {
        return rewardAddressToKeyHash(bech32) || deserializeBech32Address(bech32).stakeCredentialHash;
      },
      resolvePrivateKey: function(words) {
        return resolvePrivateKey(words);
      },
      resolveRewardAddress: function(bech32) {
        return resolveRewardAddress(bech32);
      },
      resolveEd25519KeyHash: function(bech32) {
        return resolveEd25519KeyHash(bech32);
      }
    },
    tx: {
      resolveTxHash: function(txHex) {
        return calculateTxHash(txHex);
      }
    },
    data: {
      resolveDataHash: function(data) {
        return resolveDataHash(data);
      }
    },
    script: {
      resolveScriptRef: function(script) {
        return resolveScriptRef(script);
      }
    }
  };
};
// Annotate the CommonJS export names for ESM import in node:
0 && (module.exports = {
  CSLSerializer,
  LANGUAGE_VERSIONS,
  POLICY_ID_LENGTH,
  REDEEMER_TAGS,
  addrBech32ToHex,
  addrBech32ToObj,
  applyCborEncoding,
  applyParamsToScript,
  baseAddressToStakeAddress,
  baseCertToObj,
  builderDataToCbor,
  calculateTxHash,
  castDataToPlutusData,
  castRawDataToJsonString,
  certificateToObj,
  collateralTxInToObj,
  csl,
  deserializeAddress,
  deserializeBech32Address,
  deserializeBip32PrivateKey,
  deserializeDataHash,
  deserializeEd25519KeyHash,
  deserializeEd25519Signature,
  deserializeNativeScript,
  deserializePlutusData,
  deserializePlutusScript,
  deserializePublicKey,
  deserializeScriptHash,
  deserializeScriptRef,
  deserializeTx,
  deserializeTxBody,
  deserializeTxHash,
  deserializeTxUnspentOutput,
  deserializeTxWitnessSet,
  deserializeValue,
  fromBytes,
  fromLovelace,
  fromUTF8,
  getV2ScriptHash,
  keyHashToRewardAddress,
  meshTxBuilderBodyToObj,
  mintItemToObj,
  mintParametersObj,
  nativeMintItemToObj,
  outputToObj,
  parseDatumCbor,
  parseInlineDatum,
  plutusMintItemToObj,
  poolIdBech32ToHex,
  poolIdHexToBech32,
  poolMetadataToObj,
  poolParamsToObj,
  redeemerToObj,
  relayToObj,
  resolveDataHash,
  resolveEd25519KeyHash,
  resolveNativeScriptAddress,
  resolveNativeScriptHash,
  resolveNativeScriptHex,
  resolvePlutusScriptAddress,
  resolvePrivateKey,
  resolveRewardAddress,
  resolveScriptRef,
  resolveStakeKeyHash,
  rewardAddressToKeyHash,
  scriptHashToBech32,
  scriptHashToRewardAddress,
  scriptSourceToObj,
  scriptTxInParameterToObj,
  serializeAddressObj,
  serializePlutusAddressToBech32,
  serializePoolId,
  serialzeAddress,
  signTransaction,
  simpleScriptSourceToObj,
  skeyToPubKeyHash,
  toAddress,
  toBaseAddress,
  toBytes,
  toEnterpriseAddress,
  toLovelace,
  toNativeScript,
  toPlutusData,
  toRewardAddress,
  toScriptRef,
  toUTF8,
  txInParameterToObj,
  txInToObj,
  utxoToObj,
  v2ScriptToBech32,
  withdrawalToObj
});
