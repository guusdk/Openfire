/*
 * Copyright (C) 2012 Issa Gorissen <issa-gorissen@usa.net>, 2017-2022 Ignite Realtime Foundation. All rights reserved.
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
package org.jivesoftware.openfire.crowd;

import org.dom4j.Element;
import org.jivesoftware.openfire.crowd.jaxb.User;
import org.jivesoftware.openfire.user.UserManager;
import org.jivesoftware.openfire.user.UserNotFoundException;
import org.jivesoftware.openfire.vcard.DefaultVCardProvider;
import org.jivesoftware.util.AlreadyExistsException;
import org.jivesoftware.util.NotFoundException;
import org.jivesoftware.util.SAXReaderUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutionException;

/**
 * VCard provider for Crowd.
 * 
 * <p>The name, email will be provided by crowd. All other information
 * can be managed by the XMPP client
 */
public class CrowdVCardProvider extends DefaultVCardProvider {
    private static final Logger LOG = LoggerFactory.getLogger(CrowdVCardProvider.class);
    
    private static final String VCARD_TEMPLATE
        = "<vCard xmlns=\"vcard-temp\"><FN>@displayname@</FN><N><FAMILY>@lastname@</FAMILY><GIVEN>@firstname@</GIVEN></N><NICKNAME>@nickname@</NICKNAME><EMAIL><USERID>@email@</USERID></EMAIL></vCard>";
    private static final ConcurrentHashMap<String, Object> MUTEX = new ConcurrentHashMap<>();

    /**
     * @see org.jivesoftware.openfire.vcard.DefaultVCardProvider#loadVCard(java.lang.String)
     */
    @Override
    public Element loadVCard(String username) {
        LOG.debug("loadvcard {}", username);

        if (MUTEX.containsKey(username)) {
            // preventing looping
            return null;
        }

        try {
            MUTEX.put(username, username);
            
            Element vcard = super.loadVCard(username);
            
            if (vcard == null) {
                CrowdUserProvider userProvider = (CrowdUserProvider) UserManager.getUserProvider();
                try {
                    User user = userProvider.getCrowdUser(username);
                    String str = VCARD_TEMPLATE.replace("@displayname@", user.displayName)
                            .replace("@lastname@", user.lastName)
                            .replace("@firstname@", user.firstName)
                            .replace("@email@", user.email)
                            .replace("@nickname@", username);
                    vcard = SAXReaderUtil.readRootElement(str);
                } catch (UserNotFoundException unfe) {
                    LOG.error("Unable to find user '{}' for loading its vcard", username, unfe);
                    return null;
                } catch (ExecutionException e) {
                    LOG.error("VCard parsing error", e);
                    return null;
                } catch (InterruptedException e) {
                    LOG.error("VCard parsing interrupted", e);
                    Thread.currentThread().interrupt();
                    return null;
                }

                LOG.debug(vcard != null ? vcard.asXML() : "vcard is null");

                
                // store this new vcard
                if (vcard != null) {
                    try {
                        createVCard(username, vcard);
                    } catch (AlreadyExistsException aee) {
                        LOG.error("Unable to create and store a new vcard for user:" + username + "; one already exists", aee);
                    }
                }
            }
            
            return vcard;

        } catch (RuntimeException re) {
            LOG.error("Failure occurred when loading a vcard for user:" + username, re);
            throw re;
        } finally {
            MUTEX.remove(username);
        }
    }

    /**
     * @see org.jivesoftware.openfire.vcard.DefaultVCardProvider#createVCard(java.lang.String, org.dom4j.Element)
     */
    @Override
    public Element createVCard(String username, Element vCardElement) throws AlreadyExistsException {
        LOG.debug("createvcard: {}", vCardElement.asXML());
        return super.createVCard(username, vCardElement);
    }

    /**
     * @see org.jivesoftware.openfire.vcard.DefaultVCardProvider#updateVCard(java.lang.String, org.dom4j.Element)
     */
    @Override
    public Element updateVCard(String username, Element vCard) throws NotFoundException {
        // make sure some properties have not been overridden
        Element nickNameNode = vCard.element("NICKNAME");
        Element displayNameNode = vCard.element("FN");
        
        Element nameNode = vCard.element("N");
        Element lastNameNode = nameNode.element("FAMILY");
        Element firstnameNode = nameNode.element("GIVEN");
        
        Element emailNode = vCard.element("EMAIL").element("USERID");
        
        CrowdUserProvider userProvider = (CrowdUserProvider) UserManager.getUserProvider();
        try {
            User user = userProvider.getCrowdUser(username);
            
            nickNameNode.setText(username);
            displayNameNode.setText(user.displayName);
            lastNameNode.setText(user.lastName);
            firstnameNode.setText(user.firstName);
            emailNode.setText(user.email);
            
        } catch (UserNotFoundException unfe) {
            LOG.error("Unable to find user:" + username + " for updating its vcard", unfe);
        }

        LOG.debug("updatevcard: {}", vCard.asXML());

        return super.updateVCard(username, vCard);
    }
}
