package com.thalesgroup.nl.trtdelft.cache;

public class CacheController implements CacheControllerBean {


    private ManageableCache cache;
    private CacheManager cacheManager;

    public CacheController(ManageableCache cache , CacheManager cacheManager){

        this.cache = cache;
        this.cacheManager = cacheManager;
    }







    @Override
    public boolean stopCacheManager() {
        return cacheManager.stop();
    }

    @Override
    public boolean wakeUpCacheManager() {
        return cacheManager.wakeUpNow();
    }

    @Override
    public boolean changeCacheManagerdelayMinutes(int delay) {
        return cacheManager.changeDelay(delay);
    }

    @Override
    public boolean isCacheManagerRunning() {
        return cacheManager.isRunning();
    }

    @Override
    public int getCacheSize() {
        return cache.getCacheSize();
    }

    @Override
    public int getChangeManagerDelayMinutes() {
        return cacheManager.getDelay();
    }
}
