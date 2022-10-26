#pragma once

class CScannerOptions;

class CJavaManifest {
 public:
  std::string title;
  std::string vendor;
  std::string version;
  std::string mainClass;
  std::string startClass;
  std::string createdBy;
  std::string builtBy;
  std::string buildJDK;

  CJavaManifest() {
    title.clear();
    vendor.clear();
    version.clear();
    mainClass.clear();
    startClass.clear();
    createdBy.clear();
    builtBy.clear();
    buildJDK.clear();
  }
};

class CJavaProperties {
 public:
  std::string artifactId;
  std::string groupId;
  std::string version;

  CJavaProperties() {
    artifactId.clear();
    groupId.clear();
    version.clear();
  }
};

int32_t ParseJavaManifest(std::string manifest,
                          CJavaManifest& javaManifest);
int32_t ParseJavaProperties(std::string properties,
                            CJavaProperties& javaProperties);

int32_t ProcessJavaFileJAR(CScannerOptions& options, std::wstring file, std::wstring file_physical);
int32_t ProcessJavaFileWAR(CScannerOptions& options, std::wstring file, std::wstring file_physical);
int32_t ProcessJavaFileEAR(CScannerOptions& options, std::wstring file, std::wstring file_physical);
