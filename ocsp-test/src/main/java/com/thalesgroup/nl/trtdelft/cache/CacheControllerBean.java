package com.thalesgroup.nl.trtdelft.cache;

public interface CacheControllerBean {


     boolean stopCacheManager();

    boolean wakeUpCacheManager();

    boolean changeCacheManagerdelayMinutes(int delay);

    boolean isCacheManagerRunning();

    int getCacheSize();

    int getChangeManagerDelayMinutes();
}
