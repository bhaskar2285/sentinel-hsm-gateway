package com.isc.sentinel.api.controller;

import com.isc.sentinel.api.dto.*;
import com.isc.sentinel.api.service.CryptoService;
import com.isc.sentinel.api.service.KeyService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/crypto")
@RequiredArgsConstructor
public class CryptoController {

    private final CryptoService cryptoService;
    private final KeyService    keyService;

    private static String userOf(Authentication auth) {
        return auth == null ? "anonymous" : auth.getName();
    }

    @PostMapping("/decrypt")
    @PreAuthorize("hasAuthority('OP_CRYPTO_DECRYPT')")
    public DecryptResponse decrypt(@Valid @RequestBody DecryptRequest req, Authentication auth) {
        return cryptoService.decrypt(req, userOf(auth));
    }

    @PostMapping("/encrypt")
    @PreAuthorize("hasAuthority('OP_CRYPTO_ENCRYPT')")
    public EncryptResponse encrypt(@Valid @RequestBody EncryptRequest req, Authentication auth) {
        return keyService.encrypt(req, userOf(auth));
    }

    @PostMapping("/pin/translate")
    @PreAuthorize("hasAuthority('OP_PIN_TRANSLATE')")
    public PinTranslateResponse pinTranslate(@Valid @RequestBody PinTranslateRequest req, Authentication auth) {
        return cryptoService.pinTranslate(req, userOf(auth));
    }

    @PostMapping("/pin/verify")
    @PreAuthorize("hasAuthority('OP_PIN_VERIFY')")
    public PinVerifyResponse pinVerify(@Valid @RequestBody PinVerifyRequest req, Authentication auth) {
        return cryptoService.pinVerify(req, userOf(auth));
    }

    @PostMapping("/cvv/generate")
    @PreAuthorize("hasAuthority('OP_CVV_GEN')")
    public CvvResponse cvvGenerate(@Valid @RequestBody CvvRequest req, Authentication auth) {
        return cryptoService.cvvGenerate(req, userOf(auth));
    }

    @PostMapping("/cvv/verify")
    @PreAuthorize("hasAuthority('OP_CVV_VERIFY')")
    public CvvResponse cvvVerify(@Valid @RequestBody CvvRequest req, Authentication auth) {
        return cryptoService.cvvVerify(req, userOf(auth));
    }

    @PostMapping("/arqc")
    @PreAuthorize("hasAuthority('OP_ARQC_VERIFY')")
    public ArqcResponse verifyArqc(@Valid @RequestBody ArqcRequest req, Authentication auth) {
        return cryptoService.verifyArqc(req, userOf(auth));
    }

    @PostMapping("/pin/generate")
    @PreAuthorize("hasAuthority('OP_PIN_GEN')")
    public PinGenResponse generatePin(@Valid @RequestBody PinGenRequest req, Authentication auth) {
        return cryptoService.generatePin(req, userOf(auth));
    }

    @PostMapping("/pin/pvv")
    @PreAuthorize("hasAuthority('OP_PVV_GEN')")
    public PvvGenResponse generatePvv(@Valid @RequestBody PvvGenRequest req, Authentication auth) {
        return cryptoService.generatePvv(req, userOf(auth));
    }

    @PostMapping("/pin/ibm-offset")
    @PreAuthorize("hasAuthority('OP_IBM_OFFSET_GEN')")
    public IbmOffsetResponse generateIbmOffset(@Valid @RequestBody IbmOffsetRequest req, Authentication auth) {
        return cryptoService.generateIbmOffset(req, userOf(auth));
    }

    @PostMapping("/pin/verify-visa")
    @PreAuthorize("hasAuthority('OP_PIN_VERIFY')")
    public PinVerifyResponse pinVerifyVisa(@Valid @RequestBody PinVerifyVisaRequest req, Authentication auth) {
        return cryptoService.pinVerifyVisa(req, userOf(auth));
    }

    @PostMapping("/pin/verify-interchange-ibm")
    @PreAuthorize("hasAuthority('OP_PIN_VERIFY')")
    public PinVerifyResponse interchangePinVerifyIbm(@Valid @RequestBody PinVerifyRequest req, Authentication auth) {
        return cryptoService.interchangePinVerifyIbm(req, userOf(auth));
    }

    @PostMapping("/pin/verify-interchange-visa")
    @PreAuthorize("hasAuthority('OP_PIN_VERIFY')")
    public PinVerifyResponse interchangePinVerifyVisa(@Valid @RequestBody PinVerifyVisaRequest req, Authentication auth) {
        return cryptoService.interchangePinVerifyVisa(req, userOf(auth));
    }

    @PostMapping("/pin/translate-zpk")
    @PreAuthorize("hasAuthority('OP_PIN_TRANSLATE')")
    public PinTranslateResponse pinTranslateZpk(@Valid @RequestBody PinTranslateZpkRequest req, Authentication auth) {
        return cryptoService.pinTranslateZpk(req, userOf(auth));
    }

    @PostMapping("/pin/encrypt-clear")
    @PreAuthorize("hasAuthority('OP_PIN_TRANSLATE')")
    public PinGenResponse clearPinEncrypt(@Valid @RequestBody ClearPinEncryptRequest req, Authentication auth) {
        return cryptoService.clearPinEncrypt(req, userOf(auth));
    }

    @PostMapping("/pin/derive-ibm")
    @PreAuthorize("hasAuthority('OP_PIN_VERIFY')")
    public PinDerivePinResponse derivePin(@Valid @RequestBody PinDerivePinRequest req, Authentication auth) {
        return cryptoService.derivePin(req, userOf(auth));
    }

    @PostMapping("/pin/to-lmk")
    @PreAuthorize("hasAuthority('OP_PIN_TRANSLATE')")
    public PinToLmkResponse pinToLmk(@Valid @RequestBody PinToLmkRequest req, Authentication auth) {
        return cryptoService.pinToLmk(req, userOf(auth));
    }

    @PostMapping("/pin/from-lmk")
    @PreAuthorize("hasAuthority('OP_PIN_TRANSLATE')")
    public PinFromLmkResponse pinFromLmk(@Valid @RequestBody PinFromLmkRequest req, Authentication auth) {
        return cryptoService.pinFromLmk(req, userOf(auth));
    }

    @PostMapping("/mac/generate")
    @PreAuthorize("hasAuthority('OP_MAC_GEN')")
    public MacResponse macGenerate(@Valid @RequestBody MacRequest req, Authentication auth) {
        return cryptoService.generateMac(req, userOf(auth));
    }

    @PostMapping("/mac/verify")
    @PreAuthorize("hasAuthority('OP_MAC_VRFY')")
    public MacResponse macVerify(@Valid @RequestBody MacVerifyRequest req, Authentication auth) {
        return cryptoService.verifyMac(req, userOf(auth));
    }

    @PostMapping("/key/export-zmk")
    @PreAuthorize("hasAuthority('OP_KEY_EXPORT')")
    public ExportZmkResponse exportZmk(@Valid @RequestBody ExportZmkRequest req, Authentication auth) {
        return cryptoService.exportZmk(req, userOf(auth));
    }

    @GetMapping("/hsm/status")
    @PreAuthorize("hasAuthority('OP_HSM_STATUS')")
    public HsmStatusResponse hsmStatus(Authentication auth) {
        return cryptoService.hsmStatus(userOf(auth));
    }

    @PostMapping("/hsm/echo")
    @PreAuthorize("hasAuthority('OP_HSM_ECHO')")
    public HsmEchoResponse hsmEcho(@RequestBody HsmEchoRequest req, Authentication auth) {
        return cryptoService.hsmEcho(req, userOf(auth));
    }

    @PostMapping("/key/component/generate")
    @PreAuthorize("hasAuthority('OP_KEY_COMPONENT_GEN')")
    public KeyComponentGenResponse generateKeyComponent(@RequestBody KeyComponentGenRequest req, Authentication auth) {
        return cryptoService.generateKeyComponent(req, userOf(auth));
    }

    @PostMapping("/key/form-from-components")
    @PreAuthorize("hasAuthority('OP_KEY_FORM_COMPONENTS')")
    public KeyFormComponentsResponse formKeyFromComponents(@Valid @RequestBody KeyFormComponentsRequest req, Authentication auth) {
        return cryptoService.formKeyFromComponents(req, userOf(auth));
    }

    @PostMapping("/key/check-value")
    @PreAuthorize("hasAuthority('OP_KEY_CHECK_VALUE')")
    public KeyCheckValueResponse getKeyCheckValue(@Valid @RequestBody KeyCheckValueRequest req, Authentication auth) {
        return cryptoService.getKeyCheckValue(req, userOf(auth));
    }

    @PostMapping("/arqc/emv4")
    @PreAuthorize("hasAuthority('OP_ARQC_VERIFY')")
    public ArqcResponse verifyArqcEmv4(@Valid @RequestBody ArqcRequest req, Authentication auth) {
        return cryptoService.verifyArqcEmv4(req, userOf(auth));
    }

    @PostMapping("/dcvv/verify")
    @PreAuthorize("hasAuthority('OP_DCVV_VERIFY')")
    public DcvvVerifyResponse verifyDcvv(@Valid @RequestBody DcvvVerifyRequest req, Authentication auth) {
        return cryptoService.verifyDcvv(req, userOf(auth));
    }

    @PostMapping("/csc/calculate")
    @PreAuthorize("hasAuthority('OP_CSC_CALC')")
    public CscCalcResponse calcCsc(@Valid @RequestBody CscCalcRequest req, Authentication auth) {
        return cryptoService.calcCsc(req, userOf(auth));
    }

    @PostMapping("/csc/verify")
    @PreAuthorize("hasAuthority('OP_CSC_VERIFY')")
    public CscVerifyResponse verifyCsc(@Valid @RequestBody CscVerifyRequest req, Authentication auth) {
        return cryptoService.verifyCsc(req, userOf(auth));
    }

    @PostMapping("/hmac/generate")
    @PreAuthorize("hasAuthority('OP_HMAC_GEN')")
    public HmacGenResponse generateHmac(@Valid @RequestBody HmacGenRequest req, Authentication auth) {
        return cryptoService.generateHmac(req, userOf(auth));
    }

    @PostMapping("/hmac/verify")
    @PreAuthorize("hasAuthority('OP_HMAC_VERIFY')")
    public HmacVerifyResponse verifyHmac(@Valid @RequestBody HmacVerifyRequest req, Authentication auth) {
        return cryptoService.verifyHmac(req, userOf(auth));
    }

    @PostMapping("/key/generate-tpk")
    @PreAuthorize("hasAuthority('OP_KEY_CREATE_SYM')")
    public KeyGenTpkResponse generateTpk(@Valid @RequestBody KeyGenTpkRequest req, Authentication auth) {
        return cryptoService.generateTpk(req, userOf(auth));
    }

    @PostMapping("/key/generate-zpk")
    @PreAuthorize("hasAuthority('OP_KEY_CREATE_SYM')")
    public KeyGenTpkResponse generateZpk(@Valid @RequestBody KeyGenTpkRequest req, Authentication auth) {
        return cryptoService.generateZpk(req, userOf(auth));
    }

    @PostMapping("/pin/decrypt")
    @PreAuthorize("hasAuthority('OP_PIN_TRANSLATE')")
    public PinDecryptResponse decryptPin(@Valid @RequestBody PinDecryptRequest req, Authentication auth) {
        return cryptoService.decryptPin(req, userOf(auth));
    }

    @PostMapping("/random")
    @PreAuthorize("hasAuthority('OP_HSM_STATUS')")
    public RandomDataResponse generateRandom(@RequestBody RandomDataRequest req, Authentication auth) {
        return cryptoService.generateRandom(req, userOf(auth));
    }

    @PostMapping("/pin/translate-zpk2")
    @PreAuthorize("hasAuthority('OP_PIN_TRANSLATE')")
    public PinTranslateResponse pinTranslateZpk2(@Valid @RequestBody PinTranslateZpkRequest req, Authentication auth) {
        return cryptoService.pinTranslateZpk2(req, userOf(auth));
    }

    @PostMapping("/mac/verify-alt")
    @PreAuthorize("hasAuthority('OP_MAC_VRFY')")
    public MacResponse macVerifyAlt(@Valid @RequestBody MacVerifyRequest req, Authentication auth) {
        return cryptoService.verifyMacAlt(req, userOf(auth));
    }
}
