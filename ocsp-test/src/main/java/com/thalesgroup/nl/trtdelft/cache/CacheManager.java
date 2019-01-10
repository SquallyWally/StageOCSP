package com.thalesgroup.nl.trtdelft.cache;

import com.thalesgroup.nl.trtdelft.Constants;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;


import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

public class CacheManager {

    private final boolean DO_NOT_INTERRUPT_IF_RUNNING = false;
    private ScheduledExecutorService scheduler;
    private ScheduledFuture scheduledFuture = null;
    private ManageableCache cache;
    private int cacheMaxSize;
    private int delay;
    private CacheManagingTask cacheManagingTask;
    private static final Log log = LogFactory.getLog(CacheManager.class);

    /**
     * A new cacheManager will be started on the given ManageableCache object.
     *
     * @param cache        a Manageable Cache which could be managed by this cache manager.
     * @param cacheMaxSize Maximum size of the cache. If the cache exceeds this size, LRU values will be
     *                     removed
     */

    public CacheManager(ManageableCache cache, int cacheMaxSize, int delay) {

        int NUMBER_THREADS = 1;
        scheduler = Executors.newScheduledThreadPool(NUMBER_THREADS);
        this.cache = cache;
        this.cacheMaxSize = cacheMaxSize;
        this.delay = delay;

        start();
    }

    /**
     * To start the CacheManager, it should be called only once per CacheManager in the constructor
     * CacheManager will run its TimerTask every delay number of seconds
     */
    private boolean start() {

        if (scheduledFuture == null || (scheduledFuture.isCancelled())) {
            scheduledFuture = scheduler.scheduleWithFixedDelay(cacheManagingTask, delay, delay, TimeUnit.MINUTES);
            log.info(cache.getClass().getSimpleName() + "Cache Manager has been Started");

            return true;

        }

        return false;
    }

    /**
     * To wake cacheManager up at will. If this method is called while its task is running, it will run its task again
     * soon after its done. CacheManagerTask will be rescheduled as before.
     *
     * @return true if successfully waken up. false otherwise.
     */

    public boolean wakeUpNow() {
        if (scheduledFuture != null) {
            if (!scheduledFuture.isCancelled()) {
                scheduledFuture.cancel(DO_NOT_INTERRUPT_IF_RUNNING);
            }

            scheduledFuture = scheduler.scheduleWithFixedDelay(cacheManagingTask, 0, delay, TimeUnit.MINUTES);
            log.info(cache.getClass().getSimpleName() + "Cache Manager is waking up........");

            return true;
        }

        return false;
    }


    public boolean changeDelay(int delay) throws IllegalArgumentException {

        int min = Constants.CACHE_MIN_DELAY_MINS;
        int max = Constants.CACHE_MAX_DELAY_MINS;
        if (delay < min || delay > max) {
            throw new IllegalArgumentException("The Delay should be between " + min + " and " + max + " minutes");
        }

        this.delay = delay;
        return wakeUpNow();
    }


    public int getDelay() {
        return delay;
    }

    public boolean stop() {
        if (scheduledFuture != null && !scheduledFuture.isCancelled()) {
            scheduledFuture.cancel(DO_NOT_INTERRUPT_IF_RUNNING);
            log.info(cache.getClass().getSimpleName() + "Cache Manager has been stopped......");
            return true;
        }
        return false;

    }

    public boolean isRunning() {
        return !scheduledFuture.isCancelled();
    }

    /**
     * This is the Scheduled Task the CacheManager uses in order to remove invalid cache values and
     * to remove LRU values if the cache reaches cacheMaxSize.
     */
    private class CacheManagingTask implements Runnable {

        public void run() {

            long start = System.currentTimeMillis();
            log.info(cache.getClass().getSimpleName() + " Cache Manager Task has started ");

            ManageableCacheValue nextCacheValue;

            int cacheSize = cache.getCacheSize();
            int removeNumber = (cacheSize > cacheMaxSize) ? cacheSize - cacheMaxSize : 0;

            List<ManageableCacheValue> entriesToRemove = new ArrayList<>();

            LRUEntryCollector lruEntryCollector = new LRUEntryCollector(entriesToRemove, removeNumber);

            //Start looking at cache entries
            cache.resetIter();

            while ((cacheSize--) > 0) {
                nextCacheValue = cache.getNextCacheValue();
                if (nextCacheValue == null) {
                    log.info("Cache manager iteration through Cache values has been  done");
                    break;

                }

                //Updating invalid cache values

                if (!nextCacheValue.isValid()) {
                    log.info("Updating invalid cahce value by Manager");
                    nextCacheValue.updateCacheWithNewValue();
                }

                if (removeNumber > 0) {
                    lruEntryCollector.collectEntriesToRemove(nextCacheValue);
                }
            }

            for (ManageableCacheValue oldCacheValue : entriesToRemove) {
                log.info("Removing LRU value from cache");
                oldCacheValue.removeThisCacheValue();
            }
            log.info(cache.getClass().getSimpleName() + " Cache Manager Task Done. Took " +
                    (System.currentTimeMillis() - start) + " ms.");

        }

        private class LRUEntryCollector {

            private List<ManageableCacheValue> entriesToRemove;
            private int listMaxSize;

            LRUEntryCollector(List<ManageableCacheValue> entriesToRemove, int numberToRemove){
                this.entriesToRemove = entriesToRemove;
                this.listMaxSize = numberToRemove;
            }

            /**
             * This method collects the listMaxSize number of LRU values from the Cache. These values
             * will be removed from the cache. This uses a part of the Logic in Insertion Sort.
             * @param value to be collected.
             */
            private void collectEntriesToRemove(ManageableCacheValue value) {

                entriesToRemove.add(value);
                int i = entriesToRemove.size()-1;
                int j = i;
                for(; j>0 && (value.getTimeStamp() < entriesToRemove.get(j-1).getTimeStamp()); j--) {
                    entriesToRemove.remove(j);
                    entriesToRemove.add(j,(entriesToRemove.get(j-1)));
                }
                entriesToRemove.remove(j);
                entriesToRemove.add(j,value);
                /**
                 * First entry in the list will be the oldest. Last is the earliest in the list.
                 * So remove the earliest since we need to collect the old (LRU) values to remove
                 * from cache later
                 */
                if(entriesToRemove.size() > listMaxSize) {
                    entriesToRemove.remove(entriesToRemove.size() -1);
                }
            }

        }
    }
}