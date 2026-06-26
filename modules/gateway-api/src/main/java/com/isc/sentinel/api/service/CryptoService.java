package com.isc.sentinel.api.service;

import com.isc.sentinel.api.dto.*;
import com.isc.sentinel.api.dto.DecryptRequest;
import com.isc.sentinel.api.dto.DecryptResponse;
import com.isc.sentinel.core.dispatch.CommandDispatcher;
import com.isc.sentinel.persistence.entity.HsmKey;
import com.isc.sentinel.persistence.repo.HsmKeyRepository;
import com.isc.sentinel.spi.GatewayCommand;
import com.isc.sentinel.spi.GatewayResponse;
import com.isc.sentinel.spi.HsmVendor;
import com.isc.sentinel.spi.OpCode;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class CryptoService {

    private final CommandDispatcher dispatcher;
    private final HsmKeyRepository keyRepo;

    public DecryptResponse decrypt(DecryptRequest req, String userId) {
        HsmKey k = keyRepo.findByKeyUuid(UUID.fromString(req.getKeyId()))
            .orElseThrow(() -> new IllegalArgumentException("key not found: " + req.getKeyId()));

        Map<String, Object> params = new HashMap<>();
        params.put("mode", req.getMode());
        params.put("inputFormat", req.getInputFormat());
        params.put("outputFormat", req.getOutputFormat());
        String blob = k.getEncryptedBlob() == null ? "" : new String(k.getEncryptedBlob());
        params.put("keyType", wireKeyType(blob, familyCodeForKeyType(k.getKeyType())));
        params.put("keyHex", blob);
        if (req.getIv() != null && !req.getIv().isEmpty()) {
            String sch = blob.isEmpty() ? "U" : blob.substring(0, 1);
            params.put("iv", sizeIv(req.getIv(), sch));
        }
        params.put("messageHex", req.getCiphertextHex());

        GatewayResponse resp = dispatcher.dispatch(GatewayCommand.builder()
            .op(OpCode.DATA_DECRYPT)
            .vendorHint(HsmVendor.THALES)
            .params(params)
            .keyId(req.getKeyId())
            .userId(userId)
            .build());

        return DecryptResponse.builder()
            .plaintextHex((String) resp.getResult().get("plaintext"))
            .status(resp.getStatus())
            .errCode(resp.getErrCode())
            .errText(resp.getErrText())
            .latencyMs(resp.getLatencyMs())
            .build();
    }

    private static String sizeIv(String iv, String scheme) {
        int t = (scheme != null && !scheme.isEmpty()
              && (scheme.charAt(0)=='R' || scheme.charAt(0)=='S' || scheme.charAt(0)=='H')) ? 32 : 16;
        if (iv.length() == t) return iv;
        if (iv.length() > t)  return iv.substring(0, t);
        return iv + "0".repeat(t - iv.length());
    }

    public PinTranslateResponse pinTranslate(PinTranslateRequest req, String userId) {
        HsmKey tpk = keyRepo.findByKeyUuid(UUID.fromString(req.getTpkKeyId()))
            .orElseThrow(() -> new IllegalArgumentException("TPK not found"));
        HsmKey zpk = keyRepo.findByKeyUuid(UUID.fromString(req.getZpkKeyId()))
            .orElseThrow(() -> new IllegalArgumentException("ZPK not found"));
        String tpkBlob = blobStr(tpk); String zpkBlob = blobStr(zpk);
        Map<String, Object> p = new HashMap<>();
        p.put("tpkScheme", tpkBlob.substring(0,1)); p.put("tpkHex", tpkBlob.substring(1));
        p.put("zpkScheme", zpkBlob.substring(0,1)); p.put("zpkHex", zpkBlob.substring(1));
        p.put("maxPinLen", req.getMaxPinLen());
        p.put("pinBlock", req.getPinBlock());
        p.put("pinBlockFormat", req.getPinBlockFormat());
        p.put("pan", req.getPan());
        GatewayResponse r = dispatcher.dispatch(GatewayCommand.builder()
            .op(OpCode.PIN_TRANSLATE).vendorHint(HsmVendor.THALES).params(p).userId(userId).build());
        return PinTranslateResponse.builder()
            .translatedPinBlock((String) r.getResult().get("pinBlock"))
            .status(r.getStatus()).errCode(r.getErrCode()).errText(r.getErrText()).latencyMs(r.getLatencyMs()).build();
    }

    public PinVerifyResponse pinVerify(PinVerifyRequest req, String userId) {
        HsmKey tpk = keyRepo.findByKeyUuid(UUID.fromString(req.getTpkKeyId()))
            .orElseThrow(() -> new IllegalArgumentException("TPK not found"));
        HsmKey pvk = keyRepo.findByKeyUuid(UUID.fromString(req.getPvkKeyId()))
            .orElseThrow(() -> new IllegalArgumentException("PVK not found"));
        String tpkBlob = blobStr(tpk); String pvkBlob = blobStr(pvk);
        Map<String, Object> p = new HashMap<>();
        p.put("tpkKeyType", familyCodeForKeyType(tpk.getKeyType()));
        p.put("pvkKeyType", familyCodeForKeyType(pvk.getKeyType()));
        p.put("tpkScheme", tpkBlob.substring(0,1)); p.put("tpkHex", tpkBlob.substring(1));
        p.put("pvkScheme", pvkBlob.substring(0,1)); p.put("pvkHex", pvkBlob.substring(1));
        p.put("pinBlock", req.getPinBlock()); p.put("pinBlockFormat", req.getPinBlockFormat());
        p.put("checkLen", req.getCheckLen()); p.put("pan", req.getPan());
        if (req.getDectab() != null)    p.put("dectab", req.getDectab());
        if (req.getPinOffset() != null) p.put("pinOffset", req.getPinOffset());
        GatewayResponse r = dispatcher.dispatch(GatewayCommand.builder()
            .op(OpCode.PIN_VERIFY).vendorHint(HsmVendor.THALES).params(p).userId(userId).build());
        return PinVerifyResponse.builder()
            .status(r.getStatus()).errCode(r.getErrCode()).errText(r.getErrText()).latencyMs(r.getLatencyMs()).build();
    }

    public CvvResponse cvvGenerate(CvvRequest req, String userId) {
        HsmKey cvka = keyRepo.findByKeyUuid(UUID.fromString(req.getCvkaKeyId()))
            .orElseThrow(() -> new IllegalArgumentException("CVK-A not found"));
        HsmKey cvkb = keyRepo.findByKeyUuid(UUID.fromString(req.getCvkbKeyId()))
            .orElseThrow(() -> new IllegalArgumentException("CVK-B not found"));
        String aBlob = blobStr(cvka); String bBlob = blobStr(cvkb);
        Map<String, Object> p = new HashMap<>();
        p.put("cvkaScheme", aBlob.substring(0,1)); p.put("cvkaHex", aBlob.substring(1));
        p.put("cvkbScheme", bBlob.substring(0,1)); p.put("cvkbHex", bBlob.substring(1));
        p.put("pan", req.getPan()); p.put("expDate", req.getExpDate()); p.put("serviceCode", req.getServiceCode());
        GatewayResponse r = dispatcher.dispatch(GatewayCommand.builder()
            .op(OpCode.CVV_GEN).vendorHint(HsmVendor.THALES).params(p).userId(userId).build());
        return CvvResponse.builder().cvv((String) r.getResult().get("cvv"))
            .status(r.getStatus()).errCode(r.getErrCode()).errText(r.getErrText()).latencyMs(r.getLatencyMs()).build();
    }

    public CvvResponse cvvVerify(CvvRequest req, String userId) {
        HsmKey cvka = keyRepo.findByKeyUuid(UUID.fromString(req.getCvkaKeyId()))
            .orElseThrow(() -> new IllegalArgumentException("CVK-A not found"));
        HsmKey cvkb = keyRepo.findByKeyUuid(UUID.fromString(req.getCvkbKeyId()))
            .orElseThrow(() -> new IllegalArgumentException("CVK-B not found"));
        String aBlob = blobStr(cvka); String bBlob = blobStr(cvkb);
        Map<String, Object> p = new HashMap<>();
        p.put("cvkaScheme", aBlob.substring(0,1)); p.put("cvkaHex", aBlob.substring(1));
        p.put("cvkbScheme", bBlob.substring(0,1)); p.put("cvkbHex", bBlob.substring(1));
        p.put("pan", req.getPan()); p.put("expDate", req.getExpDate());
        p.put("serviceCode", req.getServiceCode()); p.put("cvv", req.getCvv());
        GatewayResponse r = dispatcher.dispatch(GatewayCommand.builder()
            .op(OpCode.CVV_VERIFY).vendorHint(HsmVendor.THALES).params(p).userId(userId).build());
        return CvvResponse.builder()
            .status(r.getStatus()).errCode(r.getErrCode()).errText(r.getErrText()).latencyMs(r.getLatencyMs()).build();
    }

    public ArqcResponse verifyArqc(ArqcRequest req, String userId) {
        HsmKey imk = keyRepo.findByKeyUuid(UUID.fromString(req.getImkKeyId()))
            .orElseThrow(() -> new IllegalArgumentException("IMK not found"));
        String imkBlob = blobStr(imk);
        Map<String, Object> p = new HashMap<>();
        p.put("mode", req.getMode());
        p.put("imkScheme", imkBlob.substring(0,1)); p.put("imkHex", imkBlob.substring(1));
        p.put("atc", req.getAtc()); p.put("arqc", req.getArqc());
        p.put("transData", req.getTransData()); p.put("arc", req.getArc());
        p.put("pan", req.getPan()); p.put("panSeqNo", req.getPanSeqNo());
        GatewayResponse r = dispatcher.dispatch(GatewayCommand.builder()
            .op(OpCode.ARQC_VERIFY).vendorHint(HsmVendor.THALES).params(p).userId(userId).build());
        return ArqcResponse.builder().arpc((String) r.getResult().get("arpc"))
            .status(r.getStatus()).errCode(r.getErrCode()).errText(r.getErrText()).latencyMs(r.getLatencyMs()).build();
    }

    public PinGenResponse generatePin(PinGenRequest req, String userId) {
        Map<String, Object> p = new HashMap<>();
        if (req.getPan() != null) p.put("pan", req.getPan());   // JA derives the 12-digit account number
        p.put("pinLen", req.getPinLen());
        GatewayResponse r = dispatcher.dispatch(GatewayCommand.builder()
            .op(OpCode.PIN_GEN).vendorHint(HsmVendor.THALES).params(p).userId(userId).build());
        return PinGenResponse.builder()
            .pinLen(req.getPinLen())                             // JB carries no length; echo requested
            .pinUnderLmk((String) r.getResult().get("pinUnderLmk"))
            .status(r.getStatus()).errCode(r.getErrCode()).errText(r.getErrText()).latencyMs(r.getLatencyMs()).build();
    }

    public PvvGenResponse generatePvv(PvvGenRequest req, String userId) {
        HsmKey pvk = keyRepo.findByKeyUuid(UUID.fromString(req.getPvkKeyId()))
            .orElseThrow(() -> new IllegalArgumentException("PVK not found"));
        String pvkBlob = blobStr(pvk);
        Map<String, Object> p = new HashMap<>();
        p.put("pvkScheme", pvkBlob.substring(0,1)); p.put("pvkHex", pvkBlob.substring(1));
        p.put("pan", req.getPan()); p.put("pvki", req.getPvki());
        p.put("pinUnderLmk", req.getPinUnderLmk());
        // Key Block PVK (scheme S): read key + PIN under the same LMK as the key (else err 14).
        if ("S".equals(pvkBlob.substring(0,1)) && pvk.getLmkIdx() != null) {
            p.put("lmkId", String.format("%02d", pvk.getLmkIdx()));
        }
        GatewayResponse r = dispatcher.dispatch(GatewayCommand.builder()
            .op(OpCode.PVV_GEN).vendorHint(HsmVendor.THALES).params(p).userId(userId).build());
        return PvvGenResponse.builder().pvv((String) r.getResult().get("pvv"))
            .status(r.getStatus()).errCode(r.getErrCode()).errText(r.getErrText()).latencyMs(r.getLatencyMs()).build();
    }

    public IbmOffsetResponse generateIbmOffset(IbmOffsetRequest req, String userId) {
        HsmKey pvk = keyRepo.findByKeyUuid(UUID.fromString(req.getPvkKeyId()))
            .orElseThrow(() -> new IllegalArgumentException("PVK not found"));
        String pvkBlob = blobStr(pvk);
        String pan12 = req.getPan().length() > 12
            ? req.getPan().substring(req.getPan().length() - 13, req.getPan().length() - 1) : req.getPan();
        Map<String, Object> p = new HashMap<>();
        p.put("pvkKeyType", familyCodeForKeyType(pvk.getKeyType()));
        p.put("pvkScheme", pvkBlob.substring(0,1)); p.put("pvkHex", pvkBlob.substring(1));
        p.put("pinUnderLmk", req.getPinUnderLmk());
        p.put("pan", req.getPan());
        p.put("decimTable", req.getDecimTable());
        p.put("pinValidData", req.getPinValidData() != null ? req.getPinValidData() : pan12);
        p.put("checkLen", req.getCheckLen());
        // LMK id: explicit override, else for a Key Block PVK (scheme 'S') derive from the
        // stored lmkIdx so key + PIN are read under the same LMK (otherwise err 14).
        String lmkId = req.getLmkId();
        if (lmkId == null && "S".equals(pvkBlob.substring(0,1)) && pvk.getLmkIdx() != null) {
            lmkId = String.format("%02d", pvk.getLmkIdx());
        }
        if (lmkId != null) p.put("lmkId", lmkId);
        GatewayResponse r = dispatcher.dispatch(GatewayCommand.builder()
            .op(OpCode.IBM_OFFSET_GEN).vendorHint(HsmVendor.THALES).params(p).userId(userId).build());
        return IbmOffsetResponse.builder().offset((String) r.getResult().get("offset"))
            .status(r.getStatus()).errCode(r.getErrCode()).errText(r.getErrText()).latencyMs(r.getLatencyMs()).build();
    }

    public PinVerifyResponse pinVerifyVisa(PinVerifyVisaRequest req, String userId) {
        HsmKey tpk = keyRepo.findByKeyUuid(UUID.fromString(req.getTpkKeyId()))
            .orElseThrow(() -> new IllegalArgumentException("TPK not found"));
        HsmKey pvk = keyRepo.findByKeyUuid(UUID.fromString(req.getPvkKeyId()))
            .orElseThrow(() -> new IllegalArgumentException("PVK not found"));
        String tpkBlob = blobStr(tpk); String pvkBlob = blobStr(pvk);
        Map<String, Object> p = new HashMap<>();
        p.put("tpkScheme", tpkBlob.substring(0,1)); p.put("tpkHex", tpkBlob.substring(1));
        p.put("pvkScheme", pvkBlob.substring(0,1)); p.put("pvkHex", pvkBlob.substring(1));
        p.put("maxPinLen", req.getMaxPinLen()); p.put("pinBlock", req.getPinBlock());
        p.put("pinBlockFormat", req.getPinBlockFormat()); p.put("pan", req.getPan());
        p.put("pvki", req.getPvki()); p.put("pvv", req.getPvv());
        GatewayResponse r = dispatcher.dispatch(GatewayCommand.builder()
            .op(OpCode.PIN_VERIFY_VISA).vendorHint(HsmVendor.THALES).params(p).userId(userId).build());
        return PinVerifyResponse.builder()
            .status(r.getStatus()).errCode(r.getErrCode()).errText(r.getErrText()).latencyMs(r.getLatencyMs()).build();
    }

    public PinVerifyResponse interchangePinVerifyIbm(PinVerifyRequest req, String userId) {
        HsmKey tpk = keyRepo.findByKeyUuid(UUID.fromString(req.getTpkKeyId()))
            .orElseThrow(() -> new IllegalArgumentException("ZPK not found"));
        HsmKey pvk = keyRepo.findByKeyUuid(UUID.fromString(req.getPvkKeyId()))
            .orElseThrow(() -> new IllegalArgumentException("PVK not found"));
        String tpkBlob = blobStr(tpk); String pvkBlob = blobStr(pvk);
        Map<String, Object> p = new HashMap<>();
        p.put("tpkKeyType", "001"); // ZPK type for interchange
        p.put("tpkScheme", tpkBlob.substring(0,1)); p.put("tpkHex", tpkBlob.substring(1));
        p.put("pvkScheme", pvkBlob.substring(0,1)); p.put("pvkHex", pvkBlob.substring(1));
        p.put("pinBlock", req.getPinBlock()); p.put("pinBlockFormat", req.getPinBlockFormat());
        p.put("pan", req.getPan());
        if (req.getDectab() != null)    p.put("dectab", req.getDectab());
        if (req.getPinOffset() != null) p.put("pinOffset", req.getPinOffset());
        GatewayResponse r = dispatcher.dispatch(GatewayCommand.builder()
            .op(OpCode.INTERCHANGE_PIN_VERIFY_IBM).vendorHint(HsmVendor.THALES).params(p).userId(userId).build());
        return PinVerifyResponse.builder()
            .status(r.getStatus()).errCode(r.getErrCode()).errText(r.getErrText()).latencyMs(r.getLatencyMs()).build();
    }

    public PinVerifyResponse interchangePinVerifyVisa(PinVerifyVisaRequest req, String userId) {
        HsmKey tpk = keyRepo.findByKeyUuid(UUID.fromString(req.getTpkKeyId()))
            .orElseThrow(() -> new IllegalArgumentException("ZPK not found"));
        HsmKey pvk = keyRepo.findByKeyUuid(UUID.fromString(req.getPvkKeyId()))
            .orElseThrow(() -> new IllegalArgumentException("PVK not found"));
        String tpkBlob = blobStr(tpk); String pvkBlob = blobStr(pvk);
        Map<String, Object> p = new HashMap<>();
        p.put("tpkKeyType", "001"); // ZPK type for interchange
        p.put("tpkScheme", tpkBlob.substring(0,1)); p.put("tpkHex", tpkBlob.substring(1));
        p.put("pvkScheme", pvkBlob.substring(0,1)); p.put("pvkHex", pvkBlob.substring(1));
        p.put("maxPinLen", req.getMaxPinLen()); p.put("pinBlock", req.getPinBlock());
        p.put("pinBlockFormat", req.getPinBlockFormat()); p.put("pan", req.getPan());
        p.put("pvki", req.getPvki()); p.put("pvv", req.getPvv());
        GatewayResponse r = dispatcher.dispatch(GatewayCommand.builder()
            .op(OpCode.INTERCHANGE_PIN_VERIFY_VISA).vendorHint(HsmVendor.THALES).params(p).userId(userId).build());
        return PinVerifyResponse.builder()
            .status(r.getStatus()).errCode(r.getErrCode()).errText(r.getErrText()).latencyMs(r.getLatencyMs()).build();
    }

    public PinTranslateResponse pinTranslateZpk(PinTranslateZpkRequest req, String userId) {
        HsmKey src = keyRepo.findByKeyUuid(UUID.fromString(req.getSrcZpkKeyId()))
            .orElseThrow(() -> new IllegalArgumentException("srcZPK not found"));
        HsmKey dst = keyRepo.findByKeyUuid(UUID.fromString(req.getDstZpkKeyId()))
            .orElseThrow(() -> new IllegalArgumentException("dstZPK not found"));
        String srcBlob = blobStr(src); String dstBlob = blobStr(dst);
        Map<String, Object> p = new HashMap<>();
        p.put("srcZpkScheme", srcBlob.substring(0,1)); p.put("srcZpkHex", srcBlob.substring(1));
        p.put("dstZpkScheme", dstBlob.substring(0,1)); p.put("dstZpkHex", dstBlob.substring(1));
        p.put("pinBlock", req.getPinBlock()); p.put("pinBlockFormat", req.getPinBlockFormat());
        p.put("dstFlag", req.getDstFlag()); p.put("srcFlag", req.getSrcFlag());
        p.put("pan", req.getPan());
        GatewayResponse r = dispatcher.dispatch(GatewayCommand.builder()
            .op(OpCode.PIN_TRANSLATE_ZPK).vendorHint(HsmVendor.THALES).params(p).userId(userId).build());
        return PinTranslateResponse.builder()
            .translatedPinBlock((String) r.getResult().get("pinBlock"))
            .status(r.getStatus()).errCode(r.getErrCode()).errText(r.getErrText()).latencyMs(r.getLatencyMs()).build();
    }

    public PinGenResponse clearPinEncrypt(ClearPinEncryptRequest req, String userId) {
        // BA encrypts the clear PIN directly under the LMK — no ZPK, no PIN block.
        Map<String, Object> p = new HashMap<>();
        p.put("clearPin", req.getClearPin());
        p.put("pan", req.getPan());                 // BA derives the 12-digit account number
        p.put("maxPinLen", req.getMaxPinLen());
        if (req.getLmkId() != null) p.put("lmkId", req.getLmkId());
        GatewayResponse r = dispatcher.dispatch(GatewayCommand.builder()
            .op(OpCode.CLEAR_PIN_ENCRYPT).vendorHint(HsmVendor.THALES).params(p).userId(userId).build());
        return PinGenResponse.builder()
            .pinUnderLmk((String) r.getResult().get("pinUnderLmk"))
            .status(r.getStatus()).errCode(r.getErrCode()).errText(r.getErrText()).latencyMs(r.getLatencyMs()).build();
    }

    public PinDerivePinResponse derivePin(PinDerivePinRequest req, String userId) {
        HsmKey pvk = keyRepo.findByKeyUuid(UUID.fromString(req.getPvkKeyId()))
            .orElseThrow(() -> new IllegalArgumentException("PVK not found"));
        String pvkBlob = blobStr(pvk);
        Map<String, Object> p = new HashMap<>();
        p.put("pvkScheme", pvkBlob.substring(0,1)); p.put("pvkHex", pvkBlob.substring(1));
        p.put("offset", req.getOffset()); p.put("checkLen", req.getCheckLen());
        p.put("accountNo", req.getAccountNo()); p.put("decimTable", req.getDecimTable());
        p.put("pinValidData", req.getPinValidData());
        GatewayResponse r = dispatcher.dispatch(GatewayCommand.builder()
            .op(OpCode.PIN_DERIVE_IBM).vendorHint(HsmVendor.THALES).params(p).userId(userId).build());
        return PinDerivePinResponse.builder()
            .pinLen((String) r.getResult().get("pinLen")).pin((String) r.getResult().get("pin"))
            .status(r.getStatus()).errCode(r.getErrCode()).errText(r.getErrText()).latencyMs(r.getLatencyMs()).build();
    }

    public MacResponse generateMac(MacRequest req, String userId) {
        HsmKey key = keyRepo.findByKeyUuid(UUID.fromString(req.getKeyId()))
            .orElseThrow(() -> new IllegalArgumentException("MAC key not found"));
        String blob = blobStr(key);
        Map<String, Object> p = new HashMap<>();
        p.put("keyType", wireKeyType(blob, familyCodeForKeyType(key.getKeyType())));
        p.put("keyScheme", blob.substring(0,1)); p.put("keyHex", blob.substring(1));
        p.put("mode", req.getMode()); p.put("inputFormat", req.getInputFormat());
        p.put("algorithm", req.getAlgorithm()); p.put("padding", req.getPadding());
        p.put("dataHex", req.getDataHex()); p.put("iv", req.getIv());
        GatewayResponse r = dispatcher.dispatch(GatewayCommand.builder()
            .op(OpCode.MAC_GEN).vendorHint(HsmVendor.THALES).params(p).userId(userId).build());
        return MacResponse.builder().mac((String) r.getResult().get("mac"))
            .status(r.getStatus()).errCode(r.getErrCode()).errText(r.getErrText()).latencyMs(r.getLatencyMs()).build();
    }

    public MacResponse verifyMac(MacVerifyRequest req, String userId) {
        HsmKey key = keyRepo.findByKeyUuid(UUID.fromString(req.getKeyId()))
            .orElseThrow(() -> new IllegalArgumentException("MAC key not found"));
        String blob = blobStr(key);
        Map<String, Object> p = new HashMap<>();
        p.put("keyType", wireKeyType(blob, familyCodeForKeyType(key.getKeyType())));
        p.put("keyScheme", blob.substring(0,1)); p.put("keyHex", blob.substring(1));
        p.put("mode", req.getMode()); p.put("inputFormat", req.getInputFormat());
        p.put("algorithm", req.getAlgorithm()); p.put("padding", req.getPadding());
        p.put("dataHex", req.getDataHex()); p.put("iv", req.getIv()); p.put("mac", req.getMac());
        GatewayResponse r = dispatcher.dispatch(GatewayCommand.builder()
            .op(OpCode.MAC_VERIFY).vendorHint(HsmVendor.THALES).params(p).userId(userId).build());
        return MacResponse.builder()
            .status(r.getStatus()).errCode(r.getErrCode()).errText(r.getErrText()).latencyMs(r.getLatencyMs()).build();
    }

    public ExportZmkResponse exportZmk(ExportZmkRequest req, String userId) {
        HsmKey zmk = keyRepo.findByKeyUuid(UUID.fromString(req.getZmkKeyId()))
            .orElseThrow(() -> new IllegalArgumentException("ZMK not found"));
        HsmKey zpk = keyRepo.findByKeyUuid(UUID.fromString(req.getZpkKeyId()))
            .orElseThrow(() -> new IllegalArgumentException("ZPK not found"));
        String zmkBlob = blobStr(zmk); String zpkBlob = blobStr(zpk);
        Map<String, Object> p = new HashMap<>();
        p.put("zmkScheme", zmkBlob.substring(0,1)); p.put("zmkHex", zmkBlob.substring(1));
        p.put("zpkScheme", zpkBlob.substring(0,1)); p.put("zpkHex", zpkBlob.substring(1));
        GatewayResponse r = dispatcher.dispatch(GatewayCommand.builder()
            .op(OpCode.KEY_EXPORT_ZMK).vendorHint(HsmVendor.THALES).params(p).userId(userId).build());
        return ExportZmkResponse.builder()
            .scheme((String) r.getResult().get("scheme"))
            .zpkUnderZmk((String) r.getResult().get("zpkUnderZmk"))
            .kcv((String) r.getResult().get("kcv"))
            .status(r.getStatus()).errCode(r.getErrCode()).errText(r.getErrText()).latencyMs(r.getLatencyMs()).build();
    }

    public PinToLmkResponse pinToLmk(PinToLmkRequest req, String userId) {
        HsmKey key = keyRepo.findByKeyUuid(UUID.fromString(req.getKeyId()))
            .orElseThrow(() -> new IllegalArgumentException("key not found"));
        String blob = blobStr(key);
        String keyType = "ZPK".equals(req.getInputKeyScheme()) ? "001" : "008";
        Map<String, Object> p = new HashMap<>();
        p.put("keyType", keyType);
        p.put("keyScheme", blob.substring(0,1)); p.put("keyHex", blob.substring(1));
        p.put("inputKeyScheme", req.getInputKeyScheme());
        p.put("maxPinLen", req.getMaxPinLen()); p.put("pinBlock", req.getPinBlock());
        p.put("pinBlockFormat", req.getPinBlockFormat()); p.put("pan", req.getPan());
        GatewayResponse r = dispatcher.dispatch(GatewayCommand.builder()
            .op(OpCode.PIN_TO_LMK).vendorHint(HsmVendor.THALES).params(p).userId(userId).build());
        return PinToLmkResponse.builder()
            .pinLen((String) r.getResult().get("pinLen"))
            .pinUnderLmk((String) r.getResult().get("pinUnderLmk"))
            .status(r.getStatus()).errCode(r.getErrCode()).errText(r.getErrText()).latencyMs(r.getLatencyMs()).build();
    }

    public PinFromLmkResponse pinFromLmk(PinFromLmkRequest req, String userId) {
        HsmKey zpk = keyRepo.findByKeyUuid(UUID.fromString(req.getZpkKeyId()))
            .orElseThrow(() -> new IllegalArgumentException("ZPK not found"));
        String zpkBlob = blobStr(zpk);
        Map<String, Object> p = new HashMap<>();
        p.put("pinLen", req.getPinLen()); p.put("pinUnderLmk", req.getPinUnderLmk());
        p.put("zpkKeyType", familyCodeForKeyType(zpk.getKeyType()));
        p.put("zpkScheme", zpkBlob.substring(0,1)); p.put("zpkHex", zpkBlob.substring(1));
        p.put("pinBlockFormat", req.getPinBlockFormat()); p.put("pan", req.getPan());
        GatewayResponse r = dispatcher.dispatch(GatewayCommand.builder()
            .op(OpCode.PIN_FROM_LMK).vendorHint(HsmVendor.THALES).params(p).userId(userId).build());
        return PinFromLmkResponse.builder()
            .pinBlock((String) r.getResult().get("pinBlock"))
            .status(r.getStatus()).errCode(r.getErrCode()).errText(r.getErrText()).latencyMs(r.getLatencyMs()).build();
    }

    public HsmStatusResponse hsmStatus(String userId) {
        Map<String, Object> p = new HashMap<>();
        GatewayResponse r = dispatcher.dispatch(GatewayCommand.builder()
            .op(OpCode.HSM_STATUS).vendorHint(HsmVendor.THALES).params(p).userId(userId).build());
        HsmStatusResponse out = new HsmStatusResponse();
        out.setErrCode(r.getErrCode());
        out.setLmkCheckValue((String) r.getResult().get("lmkCheckValue"));
        out.setFirmware((String) r.getResult().get("firmware"));
        out.setDspFirmware((String) r.getResult().get("dspFirmware"));
        out.setSequence((String) r.getResult().get("sequence"));
        out.setFlags((String) r.getResult().get("flags"));
        return out;
    }

    public HsmEchoResponse hsmEcho(HsmEchoRequest req, String userId) {
        Map<String, Object> p = new HashMap<>();
        p.put("data", req.getData());
        GatewayResponse r = dispatcher.dispatch(GatewayCommand.builder()
            .op(OpCode.HSM_ECHO).vendorHint(HsmVendor.THALES).params(p).userId(userId).build());
        HsmEchoResponse out = new HsmEchoResponse();
        out.setErrCode(r.getErrCode());
        out.setEcho((String) r.getResult().get("echo"));
        return out;
    }

    public KeyComponentGenResponse generateKeyComponent(KeyComponentGenRequest req, String userId) {
        Map<String, Object> p = new HashMap<>();
        p.put("scheme", req.getScheme());
        p.put("keyType", req.getKeyType());
        GatewayResponse r = dispatcher.dispatch(GatewayCommand.builder()
            .op(OpCode.KEY_COMPONENT_GEN).vendorHint(HsmVendor.THALES).params(p).userId(userId).build());
        KeyComponentGenResponse out = new KeyComponentGenResponse();
        out.setErrCode(r.getErrCode());
        out.setScheme((String) r.getResult().get("scheme"));
        out.setComponent((String) r.getResult().get("component"));
        out.setKcv((String) r.getResult().get("kcv"));
        return out;
    }

    public KeyFormComponentsResponse formKeyFromComponents(KeyFormComponentsRequest req, String userId, Long bankRecId) {
        Map<String, Object> p = new HashMap<>();
        // A4 wire key type: Variant LMK = numeric code (000/001/…); Key Block LMK = "FFF".
        String wireType = ("S".equals(req.getScheme()) || "R".equals(req.getScheme()))
            ? "FFF" : buCodeForKeyType(req.getKeyType());
        p.put("keyType", wireType);
        p.put("scheme", req.getScheme());
        p.put("components", req.getComponents());
        GatewayResponse r = dispatcher.dispatch(GatewayCommand.builder()
            .op(OpCode.KEY_FORM_COMPONENTS).vendorHint(HsmVendor.THALES).params(p).userId(userId).build());
        KeyFormComponentsResponse out = new KeyFormComponentsResponse();
        out.setErrCode(r.getErrCode());
        out.setScheme((String) r.getResult().get("scheme"));
        out.setKeyUnderLmk((String) r.getResult().get("keyUnderLmk"));
        out.setKcv((String) r.getResult().get("kcv"));
        // Persist the formed key when a label is supplied so it is usable (M0/M2, KCV, …).
        if ("OK".equals(r.getStatus()) && req.getLabel() != null && !req.getLabel().isBlank()
                && out.getKeyUnderLmk() != null && !out.getKeyUnderLmk().isEmpty()) {
            String scheme = out.getScheme() != null ? out.getScheme() : req.getScheme();
            String blob = scheme + out.getKeyUnderLmk();
            boolean aes = scheme != null && (scheme.startsWith("S") || scheme.startsWith("R") || scheme.startsWith("H"));
            int bits = "T".equals(scheme) || "S".equals(scheme) ? 192 : 128;
            HsmKey saved = keyRepo.save(HsmKey.builder()
                .keyUuid(UUID.randomUUID())
                .label(req.getLabel())
                .keyType(req.getKeyType())
                .algo(aes ? "AES" : "3DES")
                .keyLengthBits(bits)
                .usage(req.getUsage())
                .ownerUserId(userId)
                .bankRecId(bankRecId)
                .kcv(out.getKcv())
                .vendorOrigin("thales")
                .encryptedBlob(blob.getBytes(java.nio.charset.StandardCharsets.US_ASCII))
                .status("ACTIVE")
                .version(1)
                .build());
            out.setKeyId(saved.getKeyUuid().toString());
        }
        return out;
    }

    public KeyCheckValueResponse getKeyCheckValue(KeyCheckValueRequest req, String userId) {
        String blob;
        String keyType;
        if (req.getKeyId() != null && !req.getKeyId().isBlank()) {
            HsmKey key = keyRepo.findByKeyUuid(UUID.fromString(req.getKeyId()))
                .orElseThrow(() -> new IllegalArgumentException("key not found: " + req.getKeyId()));
            blob = blobStr(key);
            keyType = wireKeyType(blob, req.getKeyType() != null ? req.getKeyType() : buCodeForKeyType(key.getKeyType()));
        } else if (req.getKeyHex() != null && !req.getKeyHex().isBlank()) {
            // Raw blob path — KCV of an unstored value (e.g. a key-block component).
            String scheme = req.getScheme() != null ? req.getScheme() : "U";
            blob = scheme + req.getKeyHex().toUpperCase();
            keyType = wireKeyType(blob, req.getKeyType() != null ? buCodeForKeyType(req.getKeyType()) : "00A");
        } else {
            throw new IllegalArgumentException("supply keyId or keyHex");
        }
        Map<String, Object> p = new HashMap<>();
        p.put("keyType", keyType);
        p.put("scheme", blob.substring(0,1));
        p.put("keyHex", blob.substring(1));
        GatewayResponse r = dispatcher.dispatch(GatewayCommand.builder()
            .op(OpCode.KEY_CHECK_VALUE).vendorHint(HsmVendor.THALES).params(p).userId(userId).build());
        KeyCheckValueResponse out = new KeyCheckValueResponse();
        out.setErrCode(r.getErrCode());
        out.setKcv((String) r.getResult().get("kcv"));
        return out;
    }

    public ArqcResponse verifyArqcEmv4(ArqcRequest req, String userId) {
        HsmKey imk = keyRepo.findByKeyUuid(UUID.fromString(req.getImkKeyId()))
            .orElseThrow(() -> new IllegalArgumentException("IMK not found"));
        String imkBlob = blobStr(imk);
        Map<String, Object> p = new HashMap<>();
        p.put("mode", req.getMode());
        p.put("imkScheme", imkBlob.substring(0,1)); p.put("imkHex", imkBlob.substring(1));
        p.put("atc", req.getAtc()); p.put("arqc", req.getArqc());
        p.put("transData", req.getTransData()); p.put("arc", req.getArc());
        p.put("pan", req.getPan()); p.put("panSeqNo", req.getPanSeqNo());
        GatewayResponse r = dispatcher.dispatch(GatewayCommand.builder()
            .op(OpCode.ARQC_VERIFY_EMV4).vendorHint(HsmVendor.THALES).params(p).userId(userId).build());
        return ArqcResponse.builder().arpc((String) r.getResult().get("arpc"))
            .status(r.getStatus()).errCode(r.getErrCode()).errText(r.getErrText()).latencyMs(r.getLatencyMs()).build();
    }

    private static String blobStr(HsmKey k) {
        if (k.getEncryptedBlob() == null || k.getEncryptedBlob().length < 2)
            throw new IllegalArgumentException("Key " + k.getKeyUuid() + " has no LMK material");
        return new String(k.getEncryptedBlob(), java.nio.charset.StandardCharsets.US_ASCII);
    }

    public DcvvVerifyResponse verifyDcvv(DcvvVerifyRequest req, String userId) {
        HsmKey key = keyRepo.findByKeyUuid(UUID.fromString(req.getKeyId()))
            .orElseThrow(() -> new IllegalArgumentException("MK-DCVV not found: " + req.getKeyId()));
        String blob = blobStr(key);
        String atcPadded = String.format("%06d", Long.parseLong(req.getAtc()));
        Map<String, Object> p = new HashMap<>();
        p.put("schemeId", req.getSchemeId());
        p.put("version", req.getVersion());
        p.put("keyType", "10F");
        p.put("keyScheme", blob.substring(0, 1));
        p.put("keyHex", blob.substring(1));
        p.put("keyDerivMethod", "A");
        p.put("pan", req.getPan());
        p.put("expiry", req.getExpiry());
        p.put("serviceCode", req.getServiceCode());
        p.put("atc", atcPadded);
        p.put("dcvv", req.getDcvv());
        GatewayResponse r = dispatcher.dispatch(GatewayCommand.builder()
            .op(OpCode.DCVV_VERIFY).vendorHint(HsmVendor.THALES).params(p).userId(userId).build());
        return DcvvVerifyResponse.builder()
            .verified("00".equals(r.getErrCode()))
            .status(r.getStatus()).errCode(r.getErrCode()).errText(r.getErrText())
            .latencyMs(r.getLatencyMs()).build();
    }

    public CscCalcResponse calcCsc(CscCalcRequest req, String userId) {
        HsmKey key = keyRepo.findByKeyUuid(UUID.fromString(req.getKeyId()))
            .orElseThrow(() -> new IllegalArgumentException("CSCK not found: " + req.getKeyId()));
        String blob = blobStr(key);
        String account = String.format("%19s", req.getAccount()).replace(' ', '0');
        Map<String, Object> p = new HashMap<>();
        p.put("mode", "3");
        p.put("flag", req.getFlag());
        p.put("keyType", "10F");
        p.put("keyScheme", blob.substring(0, 1));
        p.put("keyHex", blob.substring(1));
        p.put("account", account);
        p.put("expiry", req.getExpiry());
        p.put("serviceCode", req.getServiceCode());
        GatewayResponse r = dispatcher.dispatch(GatewayCommand.builder()
            .op(OpCode.CSC_CALC).vendorHint(HsmVendor.THALES).params(p).userId(userId).build());
        return CscCalcResponse.builder()
            .csc5((String) r.getResult().get("csc5"))
            .csc4((String) r.getResult().get("csc4"))
            .csc3((String) r.getResult().get("csc3"))
            .status(r.getStatus()).errCode(r.getErrCode()).errText(r.getErrText())
            .latencyMs(r.getLatencyMs()).build();
    }

    public CscVerifyResponse verifyCsc(CscVerifyRequest req, String userId) {
        HsmKey key = keyRepo.findByKeyUuid(UUID.fromString(req.getKeyId()))
            .orElseThrow(() -> new IllegalArgumentException("CSCK not found: " + req.getKeyId()));
        String blob = blobStr(key);
        String account = String.format("%19s", req.getAccount()).replace(' ', '0');
        Map<String, Object> p = new HashMap<>();
        p.put("mode", "4");
        p.put("flag", req.getFlag());
        p.put("keyType", "10F");
        p.put("keyScheme", blob.substring(0, 1));
        p.put("keyHex", blob.substring(1));
        p.put("account", account);
        p.put("expiry", req.getExpiry());
        p.put("serviceCode", req.getServiceCode());
        p.put("csc5", req.getCsc5() != null ? req.getCsc5() : "FFFFF");
        p.put("csc4", req.getCsc4() != null ? req.getCsc4() : "FFFF");
        p.put("csc3", req.getCsc3());
        GatewayResponse r = dispatcher.dispatch(GatewayCommand.builder()
            .op(OpCode.CSC_VERIFY).vendorHint(HsmVendor.THALES).params(p).userId(userId).build());
        String r3 = (String) r.getResult().get("result3");
        return CscVerifyResponse.builder()
            .result5((String) r.getResult().get("result5"))
            .result4((String) r.getResult().get("result4"))
            .result3(r3)
            .verified("00".equals(r.getErrCode()) && "0".equals(r3))
            .status(r.getStatus()).errCode(r.getErrCode()).errText(r.getErrText())
            .latencyMs(r.getLatencyMs()).build();
    }

    public HmacGenResponse generateHmac(HmacGenRequest req, String userId) {
        HsmKey key = keyRepo.findByKeyUuid(UUID.fromString(req.getKeyId()))
            .orElseThrow(() -> new IllegalArgumentException("HMAC key not found: " + req.getKeyId()));
        String blob = blobStr(key);
        Map<String, Object> p = new HashMap<>();
        p.put("hashId", req.getHashId());
        p.put("hmacLen", req.getHmacLen());
        p.put("keyType", "10F");
        p.put("keyScheme", blob.substring(0, 1));
        p.put("keyHex", blob.substring(1));
        p.put("dataHex", req.getDataHex());
        GatewayResponse r = dispatcher.dispatch(GatewayCommand.builder()
            .op(OpCode.HMAC_GEN).vendorHint(HsmVendor.THALES).params(p).userId(userId).build());
        return HmacGenResponse.builder()
            .hmac((String) r.getResult().get("hmac"))
            .status(r.getStatus()).errCode(r.getErrCode()).errText(r.getErrText())
            .latencyMs(r.getLatencyMs()).build();
    }

    public HmacVerifyResponse verifyHmac(HmacVerifyRequest req, String userId) {
        HsmKey key = keyRepo.findByKeyUuid(UUID.fromString(req.getKeyId()))
            .orElseThrow(() -> new IllegalArgumentException("HMAC key not found: " + req.getKeyId()));
        String blob = blobStr(key);
        Map<String, Object> p = new HashMap<>();
        p.put("hashId", req.getHashId());
        p.put("hmac", req.getHmac());
        p.put("keyType", "10F");
        p.put("keyScheme", blob.substring(0, 1));
        p.put("keyHex", blob.substring(1));
        p.put("dataHex", req.getDataHex());
        GatewayResponse r = dispatcher.dispatch(GatewayCommand.builder()
            .op(OpCode.HMAC_VERIFY).vendorHint(HsmVendor.THALES).params(p).userId(userId).build());
        return HmacVerifyResponse.builder()
            .verified("00".equals(r.getErrCode()))
            .status(r.getStatus()).errCode(r.getErrCode()).errText(r.getErrText())
            .latencyMs(r.getLatencyMs()).build();
    }

    public KeyGenTpkResponse generateTpk(KeyGenTpkRequest req, String userId) {
        Map<String, Object> p = new HashMap<>();
        p.put("keyScheme", req.getKeyScheme());
        GatewayResponse r = dispatcher.dispatch(GatewayCommand.builder()
            .op(OpCode.KEY_GEN_TPK).vendorHint(HsmVendor.THALES).params(p).userId(userId).build());
        String scheme = (String) r.getResult().getOrDefault("scheme", req.getKeyScheme());
        String keyHex = (String) r.getResult().getOrDefault("keyUnderLmk", "");
        String kcv    = (String) r.getResult().getOrDefault("kcv", "");
        return KeyGenTpkResponse.builder().scheme(scheme).keyUnderLmk(keyHex).kcv(kcv)
            .status(r.getStatus()).errCode(r.getErrCode()).errText(r.getErrText()).latencyMs(r.getLatencyMs()).build();
    }

    public KeyGenTpkResponse generateZpk(KeyGenTpkRequest req, String userId) {
        Map<String, Object> p = new HashMap<>();
        p.put("keyScheme", req.getKeyScheme());
        GatewayResponse r = dispatcher.dispatch(GatewayCommand.builder()
            .op(OpCode.KEY_GEN_ZPK).vendorHint(HsmVendor.THALES).params(p).userId(userId).build());
        String scheme = (String) r.getResult().getOrDefault("scheme", req.getKeyScheme());
        String keyHex = (String) r.getResult().getOrDefault("keyUnderLmk", "");
        String kcv    = (String) r.getResult().getOrDefault("kcv", "");
        return KeyGenTpkResponse.builder().scheme(scheme).keyUnderLmk(keyHex).kcv(kcv)
            .status(r.getStatus()).errCode(r.getErrCode()).errText(r.getErrText()).latencyMs(r.getLatencyMs()).build();
    }

    public PinDecryptResponse decryptPin(PinDecryptRequest req, String userId) {
        // NG decrypts an LMK-encrypted PIN — no ZPK, no PIN block. Inverse of BA.
        String pan = req.getPan();
        String pan12 = pan.length() > 12 ? pan.substring(pan.length() - 13, pan.length() - 1) : pan;
        Map<String, Object> p = new HashMap<>();
        p.put("accountNo", pan12);
        p.put("pinUnderLmk", req.getPinUnderLmk());
        GatewayResponse r = dispatcher.dispatch(GatewayCommand.builder()
            .op(OpCode.PIN_DECRYPT).vendorHint(HsmVendor.THALES).params(p).userId(userId).build());
        return PinDecryptResponse.builder()
            .clearPin((String) r.getResult().get("clearPin"))
            .referenceNumber((String) r.getResult().get("referenceNumber"))
            .status(r.getStatus()).errCode(r.getErrCode()).errText(r.getErrText()).latencyMs(r.getLatencyMs()).build();
    }

    public RandomDataResponse generateRandom(RandomDataRequest req, String userId) {
        Map<String, Object> p = new HashMap<>();
        p.put("format", req.getFormat());
        p.put("numBytes", String.valueOf(req.getNumBytes()));
        GatewayResponse r = dispatcher.dispatch(GatewayCommand.builder()
            .op(OpCode.RANDOM_DATA).vendorHint(HsmVendor.THALES).params(p).userId(userId).build());
        return RandomDataResponse.builder()
            .dataHex((String) r.getResult().get("dataHex"))
            .status(r.getStatus()).errCode(r.getErrCode()).errText(r.getErrText()).latencyMs(r.getLatencyMs()).build();
    }

    public PinTranslateResponse pinTranslateZpk2(PinTranslateZpkRequest req, String userId) {
        HsmKey src = keyRepo.findByKeyUuid(UUID.fromString(req.getSrcZpkKeyId()))
            .orElseThrow(() -> new IllegalArgumentException("srcZPK not found"));
        HsmKey dst = keyRepo.findByKeyUuid(UUID.fromString(req.getDstZpkKeyId()))
            .orElseThrow(() -> new IllegalArgumentException("dstZPK not found"));
        String srcBlob = blobStr(src); String dstBlob = blobStr(dst);
        Map<String, Object> p = new HashMap<>();
        p.put("srcZpkScheme", srcBlob.substring(0,1)); p.put("srcZpkHex", srcBlob.substring(1));
        p.put("dstZpkScheme", dstBlob.substring(0,1)); p.put("dstZpkHex", dstBlob.substring(1));
        p.put("pinBlock", req.getPinBlock()); p.put("pinBlockFormat", req.getPinBlockFormat());
        p.put("dstFlag", req.getDstFlag()); p.put("srcFlag", req.getSrcFlag());
        p.put("pan", req.getPan());
        GatewayResponse r = dispatcher.dispatch(GatewayCommand.builder()
            .op(OpCode.PIN_TRANSLATE_ZPK2).vendorHint(HsmVendor.THALES).params(p).userId(userId).build());
        return PinTranslateResponse.builder()
            .translatedPinBlock((String) r.getResult().get("pinBlock"))
            .status(r.getStatus()).errCode(r.getErrCode()).errText(r.getErrText()).latencyMs(r.getLatencyMs()).build();
    }

    public MacResponse verifyMacAlt(MacVerifyRequest req, String userId) {
        HsmKey key = keyRepo.findByKeyUuid(UUID.fromString(req.getKeyId()))
            .orElseThrow(() -> new IllegalArgumentException("MAC key not found"));
        String blob = blobStr(key);
        Map<String, Object> p = new HashMap<>();
        p.put("keyType", wireKeyType(blob, familyCodeForKeyType(key.getKeyType())));
        p.put("keyScheme", blob.substring(0,1)); p.put("keyHex", blob.substring(1));
        p.put("mode", req.getMode()); p.put("inputFormat", req.getInputFormat());
        p.put("algorithm", req.getAlgorithm()); p.put("padding", req.getPadding());
        p.put("dataHex", req.getDataHex()); p.put("iv", req.getIv()); p.put("mac", req.getMac());
        GatewayResponse r = dispatcher.dispatch(GatewayCommand.builder()
            .op(OpCode.MAC_VERIFY_ALT).vendorHint(HsmVendor.THALES).params(p).userId(userId).build());
        return MacResponse.builder()
            .status(r.getStatus()).errCode(r.getErrCode()).errText(r.getErrText()).latencyMs(r.getLatencyMs()).build();
    }

    /** Key-block (LMK scheme 'S'/'R') keys present wire key type 'FFF' — purpose is in
     *  the TR-31 descriptor. Variant keys (U/T/X/Y/Z) use their family code. */
    private static String wireKeyType(String blob, String variantCode) {
        return (blob != null && !blob.isEmpty() && (blob.charAt(0) == 'S' || blob.charAt(0) == 'R'))
            ? "FFF" : variantCode;
    }

    private static String familyCodeForKeyType(String name) {
        if (name == null) return "00A";
        return switch (name) {
            case "ZMK"  -> "000";
            case "ZPK", "BDK" -> "001";
            case "KBPK" -> "002";
            case "TAK", "003" -> "003";   // MAC key (M6/M8) — encrypted under LMK pair 16-17
            case "TMK", "TPK" -> "008";
            case "ZAK", "008" -> "008";   // MAC key (M6/M8) — encrypted under LMK pair 26-27
            case "DATA", "PVK", "CVK", "IMK-AC", "IMK-SMI", "IMK-SMC" -> "00A";
            default     -> "00A";
        };
    }

    // BU (key check value) uses different LMK pair codes than A8/A0
    // BU (Generate Key Check Value) needs the 3-digit key-type code matching the LMK pair
    // the key was GENERATED under. Mirror familyCodeForKeyType for named types; pass numeric
    // wire codes (000/001/003/402/00A…) straight through. (Earlier ZMK->001/ZPK->011 and the
    // 00A default for numeric types pointed BU at the wrong LMK pair -> errCode 10/28.)
    private static String buCodeForKeyType(String name) {
        if (name == null) return "00A";
        if (name.length() == 3 && name.chars().allMatch(c -> Character.digit(c, 16) >= 0))
            return name;
        return familyCodeForKeyType(name);
    }
}
