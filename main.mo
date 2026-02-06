import Text "mo:core/Text";
import Array "mo:core/Array";
import List "mo:core/List";
import Map "mo:core/Map";
import Blob "mo:core/Blob";
import Time "mo:core/Time";
import Order "mo:core/Order";
import Iter "mo:core/Iter";
import Principal "mo:core/Principal";
import Types "blob-storage/Storage";
import MixinAuthorization "authorization/MixinAuthorization";
import MixinStorage "blob-storage/Mixin";
import AccessControl "authorization/access-control";
import Migration "migration";

(with migration = Migration.run)
actor {
  // Integrate prefabricated components
  include MixinStorage();
  let accessControlState = AccessControl.initState();
  include MixinAuthorization(accessControlState);

  // Persistent data structures
  let detectionLogs = List.empty<DetectionLog>();
  let suspicionLogs = List.empty<SuspicionLog>();
  let alertRecords = List.empty<AlertRecord>();
  let faceTracker = Map.empty<Text, FaceTrackingData>();
  let videoHashes = Map.empty<Text, Blob>();
  let userProfiles = Map.empty<Principal, UserProfile>();

  // Data types
  public type UserProfile = {
    name : Text;
    email : Text;
    role : Text;
  };

  public type SuspectedObject = {
    name : Text;
    description : Text;
    confidence : Nat;
  };

  public type SuspicionLog = {
    id : Nat;
    videoId : Text;
    suspectedObjects : [SuspectedObject];
    suspiciousActivity : Text;
    confidence : Nat;
    timestamp : Time.Time;
  };

  public type DetectionLog = {
    id : Nat;
    videoId : Text;
    objects : [Text];
    activity : Text;
    location : Text;
    timestamp : Time.Time;
    confidence : Nat;
  };

  public type AlertRecord = {
    id : Nat;
    eventType : Text;
    description : Text;
    detectedObject : Text;
    activity : Text;
    location : Text;
    timestamp : Time.Time;
    confidence : Nat;
  };

  public type FaceTrackingData = {
    faceId : Text;
    videoId : Text;
    frame : Nat;
    coordinates : {
      x : Int;
      y : Int;
      width : Nat;
      height : Nat;
    };
    timestamp : Time.Time;
  };

  // Default comparison functions for types
  module SuspicionLog {
    public func compareByConfidenceAndTimestamp(log1 : SuspicionLog, log2 : SuspicionLog) : Order.Order {
      if (log1.confidence != log2.confidence) {
        Nat.compare(log1.confidence, log2.confidence);
      } else {
        Int.compare(log1.timestamp, log2.timestamp);
      };
    };
  };

  public type TimelineEvent = {
    description : Text;
    videoId : Text;
    eventType : Text;
    timestamp : Time.Time;
  };

  // Query endpoint to search all logs and return unified, time-sorted timeline of matching events
  public query ({ caller }) func searchEvents(searchText : Text, videoId : ?Text) : async [TimelineEvent] {
    if (not AccessControl.hasPermission(accessControlState, caller, #user)) {
      Runtime.trap("Unauthorized: Only users can search events");
    };

    let allEvents = List.empty<TimelineEvent>();

    // Filter and add detection logs
    for (detectionLog in detectionLogs.values()) {
      if (
        detectionLog.activity.contains(#text searchText) or
        detectionLog.location.contains(#text searchText) or
        detectionLog.objects.any(func(obj) { obj.contains(#text searchText) })
      ) {
        switch (videoId) {
          case (null) {
            allEvents.add(
              {
                description = detectionLog.activity;
                videoId = detectionLog.videoId;
                eventType = "detected-object";
                timestamp = detectionLog.timestamp;
              },
            );
          };
          case (?vid) {
            if (detectionLog.videoId == vid) {
              allEvents.add(
                {
                  description = detectionLog.activity;
                  videoId = detectionLog.videoId;
                  eventType = "detected-object";
                  timestamp = detectionLog.timestamp;
                },
              );
            };
          };
        };
      };
    };

    // Filter and add alert records
    for (alertRecord in alertRecords.values()) {
      if (
        alertRecord.description.contains(#text searchText) or
        alertRecord.detectedObject.contains(#text searchText) or
        alertRecord.activity.contains(#text searchText) or
        alertRecord.eventType.contains(#text searchText)
      ) {
        switch (videoId) {
          case (null) {
            allEvents.add(
              {
                description = alertRecord.description;
                videoId = alertRecord.detectedObject;
                eventType = alertRecord.eventType;
                timestamp = alertRecord.timestamp;
              },
            );
          };
          case (?vid) {
            if (alertRecord.detectedObject == vid) {
              allEvents.add(
                {
                  description = alertRecord.description;
                  videoId = alertRecord.detectedObject;
                  eventType = alertRecord.eventType;
                  timestamp = alertRecord.timestamp;
                },
              );
            };
          };
        };
      };
    };

    // Filter and add suspicion logs
    for (suspicionLog in suspicionLogs.values()) {
      if (
        suspicionLog.suspiciousActivity.contains(#text searchText) or
        suspicionLog.suspectedObjects.any(
          func(obj) { obj.description.contains(#text searchText) }
        )
      ) {
        switch (videoId) {
          case (null) {
            allEvents.add(
              {
                description = suspicionLog.suspiciousActivity;
                videoId = suspicionLog.videoId;
                eventType = "suspicious-activity";
                timestamp = suspicionLog.timestamp;
              },
            );
          };
          case (?vid) {
            if (suspicionLog.videoId == vid) {
              allEvents.add(
                {
                  description = suspicionLog.suspiciousActivity;
                  videoId = suspicionLog.videoId;
                  eventType = "suspicious-activity";
                  timestamp = suspicionLog.timestamp;
                },
              );
            };
          };
        };
      };
    };

    // Sort events by timestamp in descending order
    let allEventsArray = allEvents.toArray();
    let sortedArray = allEventsArray.sort(
      func(a, b) {
        if (a.timestamp > b.timestamp) {
          #less;
        } else if (a.timestamp < b.timestamp) { #greater } else {
          #equal;
        };
      }
    );

    sortedArray;
  };

  // ============ User Profile Management ==============
  public query ({ caller }) func getCallerUserProfile() : async ?UserProfile {
    if (not (AccessControl.hasPermission(accessControlState, caller, #user))) {
      Runtime.trap("Unauthorized: Only users can view profiles");
    };
    userProfiles.get(caller);
  };

  public query ({ caller }) func getUserProfile(user : Principal) : async ?UserProfile {
    if (not (AccessControl.hasPermission(accessControlState, caller, #user))) {
      Runtime.trap("Unauthorized: Only users can view profiles");
    };
    if (caller != user and not AccessControl.isAdmin(accessControlState, caller)) {
      Runtime.trap("Unauthorized: Can only view your own profile");
    };
    userProfiles.get(user);
  };

  public shared ({ caller }) func saveCallerUserProfile(profile : UserProfile) : async () {
    if (not (AccessControl.hasPermission(accessControlState, caller, #user))) {
      Runtime.trap("Unauthorized: Only users can save profiles");
    };
    userProfiles.add(caller, profile);
  };

  // ============ Suspicion logs ==============
  public query ({ caller }) func getSuspicionLogs(videoId : Text) : async [SuspicionLog] {
    if (not (AccessControl.hasPermission(accessControlState, caller, #user))) {
      Runtime.trap("Unauthorized: Only users can view suspicion logs");
    };
    suspicionLogs.toArray().filter(func(entry) { entry.videoId == videoId });
  };

  public query ({ caller }) func getAllSuspiciousObjects() : async [Text] {
    if (not (AccessControl.hasPermission(accessControlState, caller, #user))) {
      Runtime.trap("Unauthorized: Only users can view suspicious objects");
    };
    suspicionLogs.toArray().map<SuspicionLog, [Text]>(
      func(log) { log.suspectedObjects.map(func(obj) { obj.name }) }
    ).flatten();
  };

  public shared ({ caller }) func saveSuspicionLog(log : SuspicionLog) : async () {
    if (not (AccessControl.hasPermission(accessControlState, caller, #user))) {
      Runtime.trap("Unauthorized: Only users can save suspicion logs");
    };
    suspicionLogs.add(log);
  };

  // ============ Detection logs ==============
  public shared ({ caller }) func saveDetectionLog(log : DetectionLog) : async () {
    if (not (AccessControl.hasPermission(accessControlState, caller, #user))) {
      Runtime.trap("Unauthorized: Only users can save detection logs");
    };
    detectionLogs.add(log);
  };

  public query ({ caller }) func getDetectionLogs(videoId : Text) : async [DetectionLog] {
    if (not (AccessControl.hasPermission(accessControlState, caller, #user))) {
      Runtime.trap("Unauthorized: Only users can view detection logs");
    };
    detectionLogs.toArray().filter(func(log) { log.videoId == videoId });
  };

  public query ({ caller }) func getAllDetectionLogs() : async [DetectionLog] {
    if (not (AccessControl.hasPermission(accessControlState, caller, #user))) {
      Runtime.trap("Unauthorized: Only users can view detection logs");
    };
    detectionLogs.toArray();
  };

  // ============ Alert records ==============
  public shared ({ caller }) func saveAlertRecord(record : AlertRecord) : async () {
    if (not (AccessControl.hasPermission(accessControlState, caller, #user))) {
      Runtime.trap("Unauthorized: Only users can save alert records");
    };
    alertRecords.add(record);
  };

  public shared ({ caller }) func deleteAlertRecord(index : Nat) : async () {
    if (not (AccessControl.hasPermission(accessControlState, caller, #admin))) {
      Runtime.trap("Unauthorized: Only admins can delete alert records");
    };
    let currentArray = alertRecords.toArray();
    if (index >= currentArray.size()) {
      Runtime.trap("Invalid index: Out of bounds");
    };
    alertRecords.clear();
    for (
      record in currentArray.sliceToArray(0, index).values().concat(
        currentArray.sliceToArray(index + 1, currentArray.size()).values()
      )
    ) {
      alertRecords.add(record);
    };
  };

  public query ({ caller }) func getAllAlertRecords() : async [AlertRecord] {
    if (not (AccessControl.hasPermission(accessControlState, caller, #user))) {
      Runtime.trap("Unauthorized: Only users can view alert records");
    };
    alertRecords.toArray();
  };

  public query ({ caller }) func getAlertRecordsByType(eventType : Text) : async [AlertRecord] {
    if (not (AccessControl.hasPermission(accessControlState, caller, #user))) {
      Runtime.trap("Unauthorized: Only users can view alert records");
    };
    alertRecords.toArray().filter(func(record) { record.eventType == eventType });
  };

  public query ({ caller }) func getAlertRecordsByTimeRange(start : Time.Time, end : Time.Time) : async [AlertRecord] {
    if (not (AccessControl.hasPermission(accessControlState, caller, #user))) {
      Runtime.trap("Unauthorized: Only users can view alert records");
    };
    alertRecords.toArray().filter(func(record) { record.timestamp >= start and record.timestamp <= end });
  };

  public query ({ caller }) func getAlertRecordsByTypeAndTimeRange(eventType : Text, start : Time.Time, end : Time.Time) : async [AlertRecord] {
    if (not (AccessControl.hasPermission(accessControlState, caller, #user))) {
      Runtime.trap("Unauthorized: Only users can view alert records");
    };
    alertRecords.toArray().filter(func(record) { record.timestamp >= start and record.timestamp <= end and record.eventType == eventType });
  };

  public query ({ caller }) func getAlertRecordCount(_ : Text, start : Time.Time, end : Time.Time) : async Nat {
    if (not (AccessControl.hasPermission(accessControlState, caller, #user))) {
      Runtime.trap("Unauthorized: Only users can view alert statistics");
    };
    let filteredRecords = alertRecords.toArray().filter(
      func(record) { record.timestamp >= start and record.timestamp <= end }
    );
    filteredRecords.size();
  };

  public query ({ caller }) func getAlertRecordCountByType(eventType : Text, start : Time.Time, end : Time.Time) : async Nat {
    if (not (AccessControl.hasPermission(accessControlState, caller, #user))) {
      Runtime.trap("Unauthorized: Only users can view alert statistics");
    };
    let filteredRecords = alertRecords.toArray().filter(
      func(record) {
        record.timestamp >= start and record.timestamp <= end and record.eventType == eventType
      }
    );
    filteredRecords.size();
  };

  // ============ Video hashes ==============
  public shared ({ caller }) func saveVideoHash(videoId : Text, hash : Blob) : async () {
    if (not (AccessControl.hasPermission(accessControlState, caller, #user))) {
      Runtime.trap("Unauthorized: Only users can save video hashes");
    };
    videoHashes.add(videoId, hash);
  };

  public query ({ caller }) func getVideoHash(videoId : Text) : async Blob {
    if (not (AccessControl.hasPermission(accessControlState, caller, #user))) {
      Runtime.trap("Unauthorized: Only users can view video hashes");
    };
    switch (videoHashes.get(videoId)) {
      case (null) { Runtime.trap("No Hash Found") };
      case (?hash) { hash };
    };
  };

  // ============ Face tracking ==============
  public shared ({ caller }) func saveFaceTracking(faceId : Text, data : FaceTrackingData) : async () {
    if (not (AccessControl.hasPermission(accessControlState, caller, #user))) {
      Runtime.trap("Unauthorized: Only users can save face tracking data");
    };
    faceTracker.add(faceId, data);
  };

  public query ({ caller }) func getFaceTracking(faceId : Text) : async FaceTrackingData {
    if (not (AccessControl.hasPermission(accessControlState, caller, #user))) {
      Runtime.trap("Unauthorized: Only users can view face tracking data");
    };
    switch (faceTracker.get(faceId)) {
      case (null) { Runtime.trap("No face data found") };
      case (?data) { data };
    };
  };
};
