package com.thinkbiganalytics.metadata.jobrepo.nifi.provenance;

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import com.thinkbiganalytics.DateTimeUtil;
import com.thinkbiganalytics.activemq.config.ActiveMqConstants;
import com.thinkbiganalytics.metadata.api.OperationalMetadataAccess;
import com.thinkbiganalytics.metadata.api.event.MetadataEventService;
import com.thinkbiganalytics.metadata.api.event.feed.FeedOperationStatusEvent;
import com.thinkbiganalytics.metadata.api.feed.OpsManagerFeed;
import com.thinkbiganalytics.metadata.api.feed.OpsManagerFeedProvider;
import com.thinkbiganalytics.metadata.api.jobrepo.job.BatchJobExecutionProvider;
import com.thinkbiganalytics.metadata.api.jobrepo.nifi.NifiEvent;
import com.thinkbiganalytics.metadata.api.op.FeedOperation;
import com.thinkbiganalytics.metadata.jpa.jobrepo.nifi.NifiEventProvider;
import com.thinkbiganalytics.nifi.activemq.Queues;
import com.thinkbiganalytics.nifi.provenance.model.ProvenanceEventRecordDTO;
import com.thinkbiganalytics.nifi.provenance.model.ProvenanceEventRecordDTOHolder;
import com.thinkbiganalytics.nifi.provenance.model.util.ProvenanceEventUtil;
import com.thinkbiganalytics.nifi.rest.client.NifiRestClient;

import org.apache.commons.lang3.StringUtils;
import org.joda.time.DateTime;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jms.annotation.JmsListener;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

import javax.inject.Inject;

/**
 * JMS Listener for NiFi Provenance Events.
 */
@Component
public class ProvenanceEventReceiver {

    private static final Logger log = LoggerFactory.getLogger(ProvenanceEventReceiver.class);

    @Autowired
    private NifiEventProvider nifiEventProvider;

    @Autowired
    private BatchJobExecutionProvider nifiJobExecutionProvider;

    @Autowired
    private NifiRestClient nifiRestClient;

    @Inject
    private OperationalMetadataAccess operationalMetadataAccess;

    @Inject
    OpsManagerFeedProvider opsManagerFeedProvider;

    @Inject
    private MetadataEventService eventService;

    Cache<String, String> completedJobEvents = CacheBuilder.newBuilder().expireAfterWrite(20, TimeUnit.MINUTES).build();


    LoadingCache<String, OpsManagerFeed> opsManagerFeedCache = null;
    static OpsManagerFeed NULL_FEED = new OpsManagerFeed() {
        @Override
        public ID getId() {
            return null;
        }

        @Override
        public String getName() {
            return null;
        }

        @Override
        protected Object clone() throws CloneNotSupportedException {
            return super.clone();
        }

        @Override
        public int hashCode() {
            return super.hashCode();
        }
    };


    public ProvenanceEventReceiver(){
        opsManagerFeedCache = CacheBuilder.newBuilder().build(new CacheLoader<String, OpsManagerFeed>() {
                                                                  @Override
                                                                  public OpsManagerFeed load(String feedName) throws Exception {
                                                                      OpsManagerFeed feed =null;
                                                                      try {
                                                                            feed = operationalMetadataAccess.read(() -> {
                                                                              return opsManagerFeedProvider.findByName(feedName);
                                                                          });
                                                                      }catch (Exception e){

                                                                      }
                                                                      return feed == null ? NULL_FEED : feed;
                                                                  }

                                                              }
        );
    }

    /**
     * small cache to make sure we dont process any event more than once. The refresh/expire interval for this cache can be small since if a event comes in moore than once it would happen within a
     * second
     */
    Cache<String, DateTime> processedEvents = CacheBuilder.newBuilder().expireAfterWrite(2, TimeUnit.MINUTES).build();

    private String triggeredEventsKey(ProvenanceEventRecordDTO event) {
        return event.getJobFlowFileId() + "_" + event.getEventId();
    }

    /**
     * Process events coming from NiFi that are related to "BATCH Jobs. These will result in new JOB/STEPS to be created in Ops Manager with full provenance data
     */
    @JmsListener(destination = Queues.FEED_MANAGER_QUEUE, containerFactory = ActiveMqConstants.JMS_CONTAINER_FACTORY)
    public void receiveEvents(ProvenanceEventRecordDTOHolder events) {
        log.info("About to process {} events from the {} queue ", events.getEvents().size(), Queues.FEED_MANAGER_QUEUE);
        addEventsToQueue(events, Queues.FEED_MANAGER_QUEUE);
    }

    /**
     * Process Failure Events or Ending Job Events
     */
    @JmsListener(destination = Queues.PROVENANCE_EVENT_QUEUE, containerFactory = ActiveMqConstants.JMS_CONTAINER_FACTORY)
    public void receiveTopic(ProvenanceEventRecordDTOHolder events) {
        log.info("About to process {} events from the {} queue ", events.getEvents().size(), Queues.PROVENANCE_EVENT_QUEUE);
        addEventsToQueue(events, Queues.PROVENANCE_EVENT_QUEUE);
    }

    int maxThreads = 10;
    ExecutorService executorService =
        new ThreadPoolExecutor(
            maxThreads, // core thread pool size
            maxThreads, // maximum thread pool size
            10, // time to wait before resizing pool
            TimeUnit.SECONDS,
            new ArrayBlockingQueue<Runnable>(maxThreads, true),
            new ThreadPoolExecutor.CallerRunsPolicy());

    private Map<String, ConcurrentLinkedQueue<ProvenanceEventRecordDTO>> jobEventMap = new ConcurrentHashMap<>();


    private void addEventsToQueue(ProvenanceEventRecordDTOHolder events, String sourceJmsQueue) {
        Set<String> newJobs = new HashSet<>();

        events.getEvents().stream().sorted(ProvenanceEventUtil.provenanceEventRecordDTOComparator()).forEach(e -> {
            if (e.isBatchJob()) {
                if (!jobEventMap.containsKey(e.getJobFlowFileId())) {
                    newJobs.add(e.getJobFlowFileId());
                }
                if (isProcessBatchEvent(e, sourceJmsQueue)) {
                    jobEventMap.computeIfAbsent(e.getJobFlowFileId(), (id) -> new ConcurrentLinkedQueue()).add(e);
                }
            }

            if (e.isFinalJobEvent()) {
                notifyJobFinished(e);
            }
        });

        if (newJobs != null) {
            log.info("Submitting {} threads to process jobs ", newJobs.size());
            for (String jobId : newJobs) {
                executorService.submit(new ProcessJobEventsTask(jobId));
            }
        }

    }

    private class ProcessJobEventsTask implements Runnable {

        private String jobId;

        public ProcessJobEventsTask(String jobId) {
            this.jobId = jobId;
        }

        @Override
        public void run() {
            operationalMetadataAccess.commit(() -> {
                List<NifiEvent> nifiEvents = new ArrayList<NifiEvent>();
                try {
                    ConcurrentLinkedQueue<ProvenanceEventRecordDTO> queue = jobEventMap.get(jobId);
                    if (queue == null) {
                        jobEventMap.remove(jobId);
                    } else {
                        ProvenanceEventRecordDTO event = null;
                        while ((event = queue.poll()) != null) {
                            //   log.info("Process event {} ",event);
                            NifiEvent nifiEvent = receiveEvent(event);
                            if (nifiEvent != null) {
                                nifiEvents.add(nifiEvent);
                            }
                        }
                        jobEventMap.remove(jobId);
                        //  ((ThreadPoolExecutor)executorService).getQueue()
                    }
                } catch (Exception ex) {
                    ex.printStackTrace();
                    log.error("Error processing {} ", ex);
                }
                return nifiEvents;
            });
        }
    }

    /**
     * Return a key with the Event Id and Flow File Id to indicate that this event is currently processing.
     */
    private String processingEventMapKey(ProvenanceEventRecordDTO event) {
        return event.getEventId() + "_" + event.getFlowFileUuid();
    }

    /**
     * Enusre this incoming event didnt get processed already
     * @param event
     * @return
     */
    private boolean isProcessBatchEvent(ProvenanceEventRecordDTO event, String sourceJmsQueue) {
        //Skip batch processing for the events coming in as batch events from the Provenance Event Queue.
        // this will be processed in order when the events come in.
        if (event.isBatchJob() && Queues.PROVENANCE_EVENT_QUEUE.equalsIgnoreCase(sourceJmsQueue)) {
            //   log.info("Skip processing event {} from Jms Queue: {}. It will be processed later in order.", event,Queues.PROVENANCE_EVENT_QUEUE);
            return false;
        }

        String processingCheckMapKey = processingEventMapKey(event);
        DateTime timeAddedToQueue = processedEvents.getIfPresent(processingCheckMapKey);
        if (timeAddedToQueue == null) {
            processedEvents.put(processingCheckMapKey, DateTimeUtil.getNowUTCTime());
            return true;
        } else {
            //  log.info("Skip processing for event {}  at {} since it has already been added to a queue for processing at {} ",event, DateTimeUtil.getNowUTCTime(),timeAddedToQueue);
            return false;
        }
    }

    public NifiEvent receiveEvent(ProvenanceEventRecordDTO event) {
        NifiEvent nifiEvent = null;
        String feedName = event.getFeedName();
        if(StringUtils.isNotBlank(feedName)) {
            OpsManagerFeed feed = opsManagerFeedCache.getUnchecked(feedName);
            if(feed == null || NULL_FEED.equals(feed)) {
                log.info("Not processiong operational metadata for feed {} , event {} because it is not registered in feed manager ",feedName,event);
                opsManagerFeedCache.invalidate(feedName);
                return null;
            }
        }
        log.info("Received ProvenanceEvent {}.  is end of Job: {}.  is ending flowfile:{}, isBatch: {}", event, event.isEndOfJob(), event.isEndingFlowFileEvent(), event.isBatchJob());
        nifiEvent = nifiEventProvider.create(event);
        if (event.isBatchJob()) {
            nifiJobExecutionProvider.save(event, nifiEvent);
        }

        return nifiEvent;
    }

    private void notifyJobFinished(ProvenanceEventRecordDTO event) {
        if (event.isFinalJobEvent()) {
            String mapKey = triggeredEventsKey(event);
            String alreadyTriggered = completedJobEvents.getIfPresent(mapKey);
            if (alreadyTriggered == null) {
                completedJobEvents.put(mapKey, mapKey);
                /// TRIGGER JOB COMPLETE!!!
                if (event.isHasFailedEvents()) {
                    failedJob(event);
                } else {
                    successfulJob(event);
                }
            }
        }
    }

    /**
     * Triggered for both Batch and Streaming Feed Jobs when the Job and any related Jobs (as a result of a Merge of other Jobs are complete but have a failure in the flow<br/> Example: <br/> Job
     * (FlowFile) 1,2,3 are all running<br/> Job 1,2,3 get Merged<br/> Job 1,2 finish<br/> Job 3 finishes <br/>
     *
     * This will fire when Job3 finishes indicating this entire flow is complete<br/>
     */
    private void failedJob(ProvenanceEventRecordDTO event) {
        FeedOperation.State state = FeedOperation.State.FAILURE;
        log.info("FAILED JOB for Event {} ", event);
        this.eventService.notify(new FeedOperationStatusEvent(event.getFeedName(), null, state, "Failed Job"));
    }

    /**
     * Triggered for both Batch and Streaming Feed Jobs when the Job and any related Jobs (as a result of a Merge of other Jobs are complete<br/> Example: <br/> Job (FlowFile) 1,2,3 are all
     * running<br/> Job 1,2,3 get Merged<br/> Job 1,2 finish<br/> Job 3 finishes <br/>
     *
     * This will fire when Job3 finishes indicating this entire flow is complete<br/>
     */
    private void successfulJob(ProvenanceEventRecordDTO event) {
        FeedOperation.State state = FeedOperation.State.SUCCESS;
        log.info("Success JOB for Event {} ", event);
        this.eventService.notify(new FeedOperationStatusEvent(event.getFeedName(), null, state, "Job Succeeded for feed: "+event.getFeedName()));
    }
}