package com.thalesgroup.nl.trtdelft.cache;

public interface ManageableCache {

     ManageableCacheValue getNextCacheValue();

     int getCacheSize();

     void resetIter();
}
