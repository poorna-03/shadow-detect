import List "mo:core/List";
import Map "mo:core/Map";
import Principal "mo:core/Principal";
import Blob "mo:core/Blob";

module {
  type UserProfile = {
    name : Text;
    email : Text;
    role : Text;
  };

  type SuspectedObject = {
    name : Text;
    description : Text;
    confidence : Nat;
  };

  type SuspicionLog = {
    id : Nat;
    videoId : Text;
    suspectedObjects : [SuspectedObject];
    suspiciousActivity : Text;
    confidence : Nat;
    timestamp : Int;
  };

  type DetectionLog = {
    id : Nat;
    videoId : Text;
    objects : [Text];
    activity : Text;
    location : Text;
    timestamp : Int;
    confidence : Nat;
  };

  type AlertRecord = {
    id : Nat;
    eventType : Text;
    description : Text;
    detectedObject : Text;
    activity : Text;
    location : Text;
    timestamp : Int;
    confidence : Nat;
  };

  type FaceTrackingData = {
    faceId : Text;
    videoId : Text;
    frame : Nat;
    coordinates : {
      x : Int;
      y : Int;
      width : Nat;
      height : Nat;
    };
    timestamp : Int;
  };

  type OldActor = {
    alertRecords : List.List<AlertRecord>;
    detectionLogs : List.List<DetectionLog>;
    faceTracker : Map.Map<Text, FaceTrackingData>;
    suspicionLogs : List.List<SuspicionLog>;
    userProfiles : Map.Map<Principal, UserProfile>;
    videoHashes : Map.Map<Text, Blob>;
  };

  type NewActor = {
    alertRecords : List.List<AlertRecord>;
    detectionLogs : List.List<DetectionLog>;
    faceTracker : Map.Map<Text, FaceTrackingData>;
    suspicionLogs : List.List<SuspicionLog>;
    userProfiles : Map.Map<Principal, UserProfile>;
    videoHashes : Map.Map<Text, Blob>;
  };

  public func run(old : OldActor) : NewActor {
    // Types are unchanged!
    old;
  };
};
