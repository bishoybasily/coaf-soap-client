package com.example.coafsoapclient.service;

import com.example.coafsoapclient.service.util.CertificateUtils;
import com.example.coafsoapclient.service.util.FileSystemUtils;
import com.example.coafsoapclient.service.util.XMLUtils;
import org.springframework.stereotype.Service;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.xml.crypto.dsig.*;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import java.security.PrivateKey;
import java.util.Collections;
import java.util.List;

@Service
public class SignatureXMLA3Service {

    public String applySignature(String xml, String password) throws Exception {
        return applySignature(XMLUtils.createDocumentFrom(xml), "OCORRENCIAS", password);
    }

    private String applySignature(Document document, String signatureTag, String password) throws Exception {

        final XMLSignatureFactory factory = XMLSignatureFactory.getInstance("DOM");

        final CanonicalizationMethod cm = factory.newCanonicalizationMethod(CanonicalizationMethod.INCLUSIVE, (C14NMethodParameterSpec) null);
        final SignatureMethod sm = factory.newSignatureMethod(SignatureMethod.RSA_SHA1, null);


        Transform envelopedTransform = factory.newTransform(Transform.ENVELOPED, (TransformParameterSpec) null);
        Transform c14NTransform = factory.newTransform("http://www.w3.org/TR/2001/REC-xml-c14n-20010315", (TransformParameterSpec) null);

        List<Transform> transformList = List.of(envelopedTransform, c14NTransform);

        PrivateKey privateKey = CertificateUtils.getPrivateKeyFromPKCS12(password, FileSystemUtils.getPFXFile());
        KeyInfo ki = CertificateUtils.getKeyInfo(password, FileSystemUtils.getPFXFile(), factory);

        for (int indexNFe = 0; indexNFe < document.getDocumentElement().getElementsByTagName(signatureTag).getLength(); indexNFe++) {

            final String idUri = getIdUri(document, signatureTag);

            final DigestMethod dm = factory.newDigestMethod(DigestMethod.SHA1, null);
            final Reference ref = factory.newReference(idUri, dm, transformList, null, null);

            final SignedInfo signedInfo = factory.newSignedInfo(cm, sm, Collections.singletonList(ref));
            final XMLSignature signature = factory.newXMLSignature(signedInfo, ki);

            final Node signatureNode = document.getDocumentElement().getElementsByTagName(signatureTag).item(indexNFe);

            signature.sign(new DOMSignContext(privateKey, signatureNode));
        }

        return XMLUtils.outputXML(document);
    }

    private String getIdUri(Document document, String signerTag) {
        NodeList elements = document.getElementsByTagName(signerTag);
        Element el = (Element) elements.item(0);
        String id = el.getAttribute("ID");
        el.setIdAttribute("ID", true);
        return "#" + id;
    }


}
