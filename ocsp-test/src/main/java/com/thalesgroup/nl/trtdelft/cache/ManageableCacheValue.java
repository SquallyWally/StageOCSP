package com.thalesgroup.nl.trtdelft.cache;

public interface ManageableCacheValue {

    /**Removes dump entries*/

     boolean isValid();

     long getTimeStamp();

     void removeThisCacheValue();

     void updateCacheWithNewValue();
}
