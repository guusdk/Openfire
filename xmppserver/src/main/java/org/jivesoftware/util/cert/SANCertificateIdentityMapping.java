/*
 * Copyright (C) 2017-2025 Ignite Realtime Foundation. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.jivesoftware.util.cert;

import org.bouncycastle.asn1.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

/**
 * Certificate identity mapping that uses SubjectAlternativeName as the identity credentials.
 * This implementation returns all subjectAltName entries that are a:
 * <ul>
 * <li>GeneralName of type otherName with the "id-on-xmppAddr" Object Identifier</li>
 * <li>GeneralName of type otherName with the "id-on-dnsSRV" Object Identifier</li>
 * <li>GeneralName of type DNSName</li>
 * <li>GeneralName of type UniformResourceIdentifier</li>
 * </ul>
 *
 * @author Victor Hong
 * @author Guus der Kinderen, guus@goodbytes.nl
 */
public class SANCertificateIdentityMapping implements CertificateIdentityMapping
{

    private static final Logger Log = LoggerFactory.getLogger( SANCertificateIdentityMapping.class );

    /**
     * id-on-xmppAddr Object Identifier.
     *
     * @see <a href="http://tools.ietf.org/html/rfc6120">RFC 6120</a>
     */
    public static final String OTHERNAME_XMPP_OID = "1.3.6.1.5.5.7.8.5";

    /**
     * id-on-dnsSRV Object Identifier.
     *
     * @see <a href="https://tools.ietf.org/html/rfc4985">RFC 4985</a>
     */
    public static final String OTHERNAME_SRV_OID = "1.3.6.1.5.5.7.8.7";
    
    /**
     * User Principal Name (UPN) Object Identifier.
     *
     * @see <a href="http://www.oid-info.com/get/1.3.6.1.4.1.311.20.2.3">User Principal Name (UPN)</a>
     */
    public static final String OTHERNAME_UPN_OID = "1.3.6.1.4.1.311.20.2.3";

    
    /**
     * Returns the JID representation of an XMPP entity contained as a SubjectAltName extension
     * in the certificate. If none was found then return an empty list.
     *
     * @param certificate the certificate presented by the remote entity.
     * @return the JID representation of an XMPP entity contained as a SubjectAltName extension
     * in the certificate. If none was found then return an empty list.
     */
    @Override
    public List<String> mapIdentity( X509Certificate certificate )
    {
        List<String> identities = new ArrayList<>();
        try
        {
            Collection<List<?>> altNames = certificate.getSubjectAlternativeNames();
            // Check that the certificate includes the SubjectAltName extension
            if ( altNames == null )
            {
                return Collections.emptyList();
            }
            for ( List<?> item : altNames )
            {
                final Integer type = (Integer) item.get( 0 );
                final Object value = item.get( 1 ); // this is either a string, or a byte-array that represents the ASN.1 DER encoded form.
                final String result = switch (type) {
                    case 0 -> // OtherName: search for "id-on-xmppAddr" or 'sRVName' or 'userPrincipalName'
                        parseOtherName((byte[]) value);
                    case 2 -> // DNS
                        (String) value;
                    case 6 -> // URI
                        (String) value;
                    default -> // Not applicable to XMPP, so silently ignore them
                        null;
                };

                if ( result != null )
                {
                    identities.add( result );
                }
            }
        }
        catch ( CertificateParsingException e )
        {
            Log.error( "Error parsing SubjectAltName in certificate: " + certificate.getSubjectDN(), e );
        }
        return identities;
    }

    /**
     * Returns the short name of mapping.
     *
     * @return The short name of the mapping (never null).
     */
    @Override
    public String name()
    {
        return "Subject Alternative Name Mapping";
    }

    /**
     * Parses the byte-array representation of a subjectAltName 'otherName' entry.
     * <p>
     * The provided 'OtherName' is expected to have this format:
     * <pre>{@code
     * OtherName ::= SEQUENCE {
     * type-id    OBJECT IDENTIFIER,
     * value      [0] EXPLICIT ANY DEFINED BY type-id }
     * }</pre>
     *
     * @param item A byte array representation of a subjectAltName 'otherName' entry (cannot be null).
     * @return an xmpp address, or null when the otherName entry does not relate to XMPP (or fails to parse).
     */
    public String parseOtherName( byte[] item )
    {
        if ( item == null || item.length == 0 )
        {
            return null;
        }

        try ( final ASN1InputStream decoder = new ASN1InputStream( item ) )
        {
            ASN1Primitive object = decoder.readObject();
            if (object instanceof DLTaggedObject) {
                final DLTaggedObject taggedObject = (DLTaggedObject) object;
                object = (ASN1Sequence) taggedObject.getBaseObject();
            }

            // By specification, OtherName instances must always be an ASN.1 Sequence.
            final ASN1Sequence otherNameSeq = (ASN1Sequence) object;

            // By specification, an OtherName instance consists of:
            // - the type-id (which is an Object Identifier), followed by:
            // - a tagged value, of which the tag number is 0 (zero) and the value is defined by the type-id.
            final ASN1ObjectIdentifier typeId = (ASN1ObjectIdentifier) otherNameSeq.getObjectAt( 0 );
            final ASN1TaggedObject taggedValue = (ASN1TaggedObject) otherNameSeq.getObjectAt( 1 );

            final int tagNo = taggedValue.getTagNo();
            if ( tagNo != 0 )
            {
                throw new IllegalArgumentException( "subjectAltName 'otherName' sequence's second object is expected to be a tagged value of which the tag number is 0. The tag number that was detected: " + tagNo );
            }
            final ASN1Primitive value = taggedValue.toASN1Primitive();

            switch ( typeId.getId() )
            {
                case OTHERNAME_SRV_OID:
                    return parseOtherNameDnsSrv( value );

                case OTHERNAME_XMPP_OID:
                    return parseOtherNameXmppAddr( value );
                    
                case OTHERNAME_UPN_OID:
                    return parseOtherNameUpn( value );

                default:
                    String otherName = parseOtherName(typeId, value);
                    if (otherName != null) {
                        return otherName;
                    }
                    Log.debug( "Ignoring subjectAltName 'otherName' type-id '{}' that's neither id-on-xmppAddr nor id-on-dnsSRV.", typeId.getId() );
                    return null;
            }
        }
        catch ( Exception e )
        {
            Log.warn( "Unable to parse a byte array (of length {}) as a subjectAltName 'otherName'. It is ignored.", item.length, e );
            return null;
        }
    }

    /**
     * Allow sub-class to support additional OID values, possibly taking typeId into account
     *
     * @param typeId The ASN.1 object identifier (cannot be null).
     * @param value The ASN.1 representation of the value (cannot be null).
     * @return The parsed otherName String value.
     */
    protected String parseOtherName(ASN1ObjectIdentifier typeId, ASN1Primitive value) {
        return null;
    }
    
    /**
     * Parses a SRVName value as specified by RFC 4985.
     *
     * This method parses the argument value as a DNS SRV Resource Record. Only when the parsed value refers to an XMPP
     * related service, the corresponding DNS domain name is returned (minus the service name).
     *
     * @param srvName The ASN.1 representation of the srvName value (cannot be null).
     * @return an XMPP address value, or null when the record does not relate to XMPP.
     */
    protected String parseOtherNameDnsSrv( ASN1Primitive srvName )
    {
        // RFC 4985 says that this should be a IA5 String.
        final ASN1TaggedObject taggedObject = (ASN1TaggedObject) srvName;
        final ASN1IA5String instance = ASN1IA5String.getInstance(taggedObject, true);
        final String value = instance.getString();

        if ( value.toLowerCase().startsWith( "_xmpp-server." ) )
        {
            return value.substring( "_xmpp-server.".length() );
        }
        else if ( value.toLowerCase().startsWith( "_xmpp-client." ) )
        {
            return value.substring( "_xmpp-client.".length() );
        }
        else
        {
            // Not applicable to XMPP. Ignore.
            Log.debug( "srvName value '{}' of id-on-dnsSRV record is neither _xmpp-server nor _xmpp-client. It is being ignored.", value );
            return null;
        }
    }

    /**
     * Parse a XmppAddr value as specified in RFC 6120.
     *
     * @param xmppAddr The ASN.1 representation of the xmppAddr value (cannot be null).
     * @return The parsed xmppAddr value.
     */
    protected String parseOtherNameXmppAddr( ASN1Primitive xmppAddr )
    {
        // RFC 6120 says that this should be a UTF8String.
        final ASN1TaggedObject taggedObject = (ASN1TaggedObject) xmppAddr;
        final ASN1UTF8String instance = ASN1UTF8String.getInstance(taggedObject, true);
        return instance.getString();
    }
    
    /**
     * Parse a UPN value 
     *
     * @param value The ASN.1 representation of the UPN (cannot be null).
     * @return The parsed UPN value.
     */
    protected String parseOtherNameUpn( ASN1Primitive value )
    {
        String otherName = null;
        if (value instanceof ASN1TaggedObject) {
            final ASN1TaggedObject taggedObject = (ASN1TaggedObject) value;
            final ASN1UTF8String instance = ASN1UTF8String.getInstance(taggedObject, true);
            otherName = instance.getString();
        }
        if (otherName == null) {
            Log.warn("UPN type unexpected, UPN extraction failed: " + value.getClass().getName() + ":" + value.toString());
        } else {
            Log.debug("UPN from certificate has value of: " + otherName );
        }
        return otherName;
    }    
}
