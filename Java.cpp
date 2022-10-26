
#include "stdafx.h"
#include "Utils.h"
#include "Reports.h"
#include "Scanner.h"
#include "Java.h"


bool IsCVE202242889Mitigated(CJavaManifest& javaManifest) {
  int major = 0, minor = 0, build = 0;
  if (ParseVersion(javaManifest.version, major, minor, build)) {
    if ((major == 1) && (minor < 5)) return true;
    if ((major == 1) && (minor > 9)) return true;
    if ((major > 1)) return true;
  }
  return false;
}

bool IsCVE202242889Mitigated(CJavaProperties& javaProperties) {
  int major = 0, minor = 0, build = 0;
  if (ParseVersion(javaProperties.version, major, minor, build)) {
    if ((major == 1) && (minor < 5)) return true;
    if ((major == 1) && (minor > 9)) return true;
    if ((major > 1)) return true;
  }
  return false;
}

int32_t ParseJavaManifest(std::string manifest, CJavaManifest& javaManifest) {
  int32_t rv = ERROR_SUCCESS;
  bool    found = false;

  SanitizeContents(manifest);

  found = GetDictionaryValue(manifest, "Implementation-Title:", "Unknown", javaManifest.title);
  if (!found) {
    GetDictionaryValue(manifest, "Bundle-Title:", "Unknown", javaManifest.title);
  }

  found = GetDictionaryValue(manifest, "Implementation-Vendor-Id:", "Unknown", javaManifest.vendor);
  if (!found) {
    found = GetDictionaryValue(manifest, "Implementation-Vendor:", "Unknown", javaManifest.vendor);
    if (!found) {
      GetDictionaryValue(manifest, "Bundle-Vendor:", "Unknown", javaManifest.vendor);
    }
  }

  found = GetDictionaryValue(manifest, "Implementation-Version:", "Unknown", javaManifest.version);
  if (!found) {
    GetDictionaryValue(manifest, "Bundle-Version:", "Unknown", javaManifest.version);
  }

  GetDictionaryValue(manifest, "Built-By:", "", javaManifest.builtBy);
  GetDictionaryValue(manifest, "Created-By:", "", javaManifest.createdBy);
  GetDictionaryValue(manifest, "Build-Jdk:", "", javaManifest.buildJDK);

  GetDictionaryValue(manifest, "Main-Class:", "", javaManifest.mainClass);
  GetDictionaryValue(manifest, "Start-Class:", "", javaManifest.startClass);

  StripWhitespace(javaManifest.title);
  StripWhitespace(javaManifest.vendor);
  StripWhitespace(javaManifest.version);
  StripWhitespace(javaManifest.builtBy);
  StripWhitespace(javaManifest.createdBy);
  StripWhitespace(javaManifest.buildJDK);
  StripWhitespace(javaManifest.mainClass);
  StripWhitespace(javaManifest.startClass);

  return rv;
}

int32_t ParseJavaProperties(std::string properties, CJavaProperties& javaProperties) {
  int32_t rv = ERROR_SUCCESS;

  SanitizeContents(properties);

  GetDictionaryValue(properties, "artifactId=", "Unknown", javaProperties.artifactId);
  GetDictionaryValue(properties, "groupId=", "Unknown", javaProperties.groupId);
  GetDictionaryValue(properties, "version=", "Unknown", javaProperties.version);

  StripWhitespace(javaProperties.artifactId);
  StripWhitespace(javaProperties.groupId);
  StripWhitespace(javaProperties.version);

  return rv;
}

int32_t ProcessJavaFileWAR(CScannerOptions& options, std::wstring file, std::wstring file_physical) {
  int32_t rv = ERROR_SUCCESS;
  return rv;
}


int32_t ProcessJavaFileEAR(CScannerOptions& options, std::wstring file, std::wstring file_physical) {
  int32_t rv = ERROR_SUCCESS;
  return rv;
}

int32_t ProcessJavaFileJAR(CScannerOptions& options, std::wstring file, std::wstring file_physical) {
  int32_t                   rv = ERROR_SUCCESS;
  unzFile                   zf = NULL;
  unz_file_info64           file_info;
  char*                     p = NULL;
  char                      filename[_MAX_PATH + 1];
  std::wstring              wFilename;
  std::wstring              tmpFilename;
  bool                      foundManifest = false;
  bool                      foundProperties = false;
  bool                      foundApacheCommonsText = false;
  std::string               manifest;
  std::string               properties;
  CJavaManifest             javaManifest;
  CJavaProperties           javaProperties;
  std::vector<std::wstring> wdependencies;
  std::string               cveStatus = "Unknown";
  bool                      cve202242889Mitigated = false;

  zlib_filefunc64_def zfm = { 0 };
  fill_win32_filefunc64W(&zfm);

  if (!file_physical.empty()) {
    zf = unzOpen2_64(file_physical.c_str(), &zfm);
  } else {
    zf = unzOpen2_64(file.c_str(), &zfm);
  }
  if (NULL != zf) {

    rv = unzGoToFirstFile(zf);
    if (UNZ_OK == rv) {
      do {
        rv = unzGetCurrentFileInfo64(zf, &file_info, filename, _countof(filename), NULL, 0, NULL, 0);
        if (UNZ_OK == rv) {
          if (0 == stricmp(filename, "META-INF/MANIFEST.MF")) {
            foundManifest = true;
            UncompressZIPContentsToString(zf, manifest);
          }
          if (0 == stricmp(filename, "META-INF/maven/org.apache.commons/commons-text/pom.properties")) {
            foundProperties = true;
            UncompressZIPContentsToString(zf, properties);
          }
        }
        rv = unzGoToNextFile(zf);
      } while (UNZ_END_OF_LIST_OF_FILE != rv);
    }
    unzClose(zf);
  }
  rv = ERROR_SUCCESS;

  if (foundManifest) {
    ParseJavaManifest(manifest, javaManifest);
  }
  if (foundProperties) {
    ParseJavaProperties(properties, javaProperties);
  }

  if (javaManifest.title == "Apache Commons Text") {
    foundApacheCommonsText = true;
    if (IsCVE202242889Mitigated(javaManifest)) {
      cve202242889Mitigated = true;
      cveStatus = "Mitigated";
    } else {
      repSummary.foundVunerabilities++;
      cveStatus = "Potentially Vulnerable ( CVE-2022-202242889: Found )";
    }

    repVulns.push_back(CReportVulnerabilities(
        file, A2W(javaManifest.title), A2W(javaManifest.vendor), A2W(javaManifest.version), A2W(cveStatus), cve202242889Mitigated, A2W(javaManifest.version)
    ));

    if (options.console) {
      wprintf(L"Apache Commons Text Found: '%s' ( Manifest Title: %S, Manifest Vendor: %S, Manifest Version: %S, CVE Status: %S )\n",
              file.c_str(), javaManifest.title.c_str(), javaManifest.vendor.c_str(), javaManifest.version.c_str(), cveStatus.c_str()
      );
    }
  } else if ((javaProperties.artifactId == "commons-text") && (javaProperties.groupId == "org.apache.commons")) {
    foundApacheCommonsText = true;
    if (IsCVE202242889Mitigated(javaProperties)) {
      cve202242889Mitigated = true;
      cveStatus = "Mitigated";
    } else {
      repSummary.foundVunerabilities++;
      cveStatus = "Potentially Vulnerable ( CVE-2022-202242889: Found )";
    }

    if (options.console) {
      wprintf(L"Apache Commons Text Found: '%s' ( Manifest Title: %S, Manifest Vendor: %S, Manifest Version: %S, CVE Status: %S )\n",
              file.c_str(), javaManifest.title.c_str(), javaManifest.vendor.c_str(), javaManifest.version.c_str(), cveStatus.c_str()
      );
    }
  }

  if (foundApacheCommonsText) {
    repVulns.push_back(CReportVulnerabilities(
        file, A2W(javaManifest.title), A2W(javaManifest.vendor), A2W(javaManifest.version), A2W(cveStatus), cve202242889Mitigated, A2W(javaProperties.version)
    ));
  }
  return rv;
}
