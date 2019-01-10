package com.thalesgroup.nl.trtdelft.crl;

import com.thalesgroup.nl.trtdelft.cache.CacheController;
import com.thalesgroup.nl.trtdelft.cache.CacheManager;
import com.thalesgroup.nl.trtdelft.cache.ManageableCache;
import com.thalesgroup.nl.trtdelft.cache.ManageableCacheValue;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.synapse.commons.jmx.MBeanRegistrar;


import java.security.cert.X509CRL;
import java.util.Date;
import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class CRLCache implements ManageableCache {

    private static volatile CRLCache cache;
    private static volatile Map<String, CRLCacheValue> hashMap = new ConcurrentHashMap<String, CRLCacheValue>();
    private static volatile Iterator<Map.Entry<String, CRLCacheValue>> iterator = hashMap.entrySet().iterator();
    private static volatile CacheManager cacheManager;
    private static CRLVerifier crlVerifier = new CRLVerifier(null);
    private static final Log log = LogFactory.getLog(CRLCache.class);

    private CRLCache() {
    }

    public static CRLCache getCache() {
        //Double checked locking
        if (cache == null) {
            synchronized (CRLCache.class) {
                if (cache == null) {
                    cache = new CRLCache();
                }
            }
        }
        return cache;
    }

    /**
     * This initialize the Cache with a CacheManager. If this method is called, a cache manager will not be used.
     *
     * @param size max size of the cache
     * @param delay defines how frequently the CacheManager will be started
     */
    public void init(int size, int delay) {
        if (cacheManager == null) {
            synchronized (CRLCache.class) {
                if (cacheManager == null) {
                    cacheManager = new CacheManager(cache, size, delay);
                    CacheController mbean = new CacheController(cache,cacheManager);
                    MBeanRegistrar.getInstance().registerMBean(mbean, "CacheController", "CRLCacheController");
                }
            }
        }
    }

    /**
     * This method is needed by the cache Manager to go through the cache entries to remove invalid values or
     * to remove LRU cache values if the cache has reached its max size.
     * Todo: Can move to an abstract class.
     *
     * @return next cache value of the cache.
     */
    public synchronized ManageableCacheValue getNextCacheValue() {
        //changes to the map are reflected on the keySet. And its iterator is weakly consistent. so will never
        //throw concurrent modification exception.
        if (iterator.hasNext()) {
            return hashMap.get(iterator.next().getKey());
        } else {
            resetIter();
            return null;
        }
    }

    /**
     * To get the current cache size (size of the hash map).
     */
    public synchronized int getCacheSize() {
        return hashMap.size();
    }

    public void resetIter() {
        iterator = hashMap.entrySet().iterator();
    }

    private synchronized void replaceNewCacheValue(CRLCacheValue cacheValue) {
        //If someone has updated with the new value before current Thread.
        if (cacheValue.isValid())
            return;

        try {
            String crlUrl = cacheValue.crlUrl;
            X509CRL x509CRL = crlVerifier.downloadCRLFromWeb(crlUrl);
            this.setCacheValue(crlUrl, x509CRL);
        } catch (Exception e) {
            log.info("Cant replace old CacheValue with new CacheValue. So remove", e);
            //If cant be replaced remove.
            cacheValue.removeThisCacheValue();
        }
    }

    public synchronized X509CRL getCacheValue(String crlUrl) {
        CRLCacheValue cacheValue = hashMap.get(crlUrl);
        if (cacheValue != null) {
            //If who ever gets this cache value before Cache manager task found its invalid, update it and get the
            // new value.
            if (!cacheValue.isValid()) {
                cacheValue.updateCacheWithNewValue();
                CRLCacheValue crlCacheValue = hashMap.get(crlUrl);
                return (crlCacheValue != null ? crlCacheValue.getValue() : null);
            }

            return cacheValue.getValue();
        } else
            return null;
    }

    public synchronized void setCacheValue(String crlUrl, X509CRL crl) {
        CRLCacheValue cacheValue = new CRLCacheValue(crlUrl, crl);
        log.info("Before set- HashMap size " + hashMap.size());
        hashMap.put(crlUrl, cacheValue);
        log.info("After set - HashMap size " + hashMap.size());
    }

    public synchronized void removeCacheValue(String crlUrl) {
        log.info("Before remove - HashMap size " + hashMap.size());
        hashMap.remove(crlUrl);
        log.info("After remove - HashMap size " + hashMap.size());

    }

    /**
     * This is the wrapper class of the actual cache value which is a X509CRL.
     */
    private class CRLCacheValue implements ManageableCacheValue {

        private String crlUrl;
        private X509CRL crl;
        private long timeStamp = System.currentTimeMillis();

        public CRLCacheValue(String crlUrl, X509CRL crl) {
            this.crlUrl = crlUrl;
            this.crl = crl;
        }

        public String getKey() {
            return crlUrl;
        }

        public X509CRL getValue() {
            timeStamp = System.currentTimeMillis();
            return crl;
        }

        /**
         * CRL has a validity period. We can reuse a downloaded CRL within that period.
         */
        public boolean isValid() {
            Date today = new Date();
            Date nextUpdate = crl.getNextUpdate();
            return nextUpdate != null && nextUpdate.after(today);
        }

        public long getTimeStamp() {
            return timeStamp;
        }

        /**
         * Used by cacheManager to remove invalid entries.
         */
        public void removeThisCacheValue() {
            removeCacheValue(crlUrl);
        }

        public void updateCacheWithNewValue() {
            replaceNewCacheValue(this);
        }
    }
}
