#include "esp_ghota.h"

#include <esp_app_format.h>
#include <esp_crt_bundle.h>
#include <esp_event.h>
#include <esp_http_client.h>
#include <esp_https_ota.h>
#include <esp_log.h>
#include <esp_ota_ops.h>
#include <esp_tls.h>
#include <fnmatch.h>
#include <freertos/FreeRTOS.h>
#include <freertos/event_groups.h>
#include <freertos/task.h>
#include <libgen.h>
#include <sdkconfig.h>
#include <stdlib.h>

#include "lwjson.h"

static const char *TAG = "GHOTA";

ESP_EVENT_DEFINE_BASE(GHOTA_EVENTS);

typedef struct ghota_client_handle_t {
    ghota_config_t config;
    char *username;
    char *token;

    struct
    {
        char tagName[CONFIG_MAX_FILENAME_LEN];
        char fwUrl[CONFIG_MAX_URL_LEN];
        char storageUrl[CONFIG_MAX_URL_LEN];
        uint8_t flags;
    } result;

    struct
    {
        char name[CONFIG_MAX_FILENAME_LEN];
        char url[CONFIG_MAX_URL_LEN];
    } scratch;

    semver_t currentversion;
    semver_t latestVersion;
    uint32_t countdown;
    const esp_partition_t *storagePartition;
} ghota_client_handle_t;

enum release_flags {
    GHOTA_RELEASE_GOT_TAG = 0x01,
    GHOTA_RELEASE_GOT_BINARY_NAME = 0x02,
    GHOTA_RELEASE_GOT_BINARY_URL = 0x04,
    GHOTA_RELEASE_VALID_STORAGE = 0x08,
    GHOTA_RELEASE_VALID_FIRMWARE = 0x10,
} release_flags;

SemaphoreHandle_t ghota_lock = NULL;

static void SetFlag(ghota_client_handle_t *handle, enum release_flags flag) {
    handle->result.flags |= flag;
}
static bool GetFlag(ghota_client_handle_t *handle, enum release_flags flag) {
    return handle->result.flags & flag;
}

/*static void ClearFlag(ghota_client_handle_t *handle, enum release_flags flag) {
    handle->result.flags &= ~flag;
}*/

ghota_client_handle_t *ghota_init(ghota_config_t *newconfig) {
    if (!ghota_lock) {
        ghota_lock = xSemaphoreCreateMutex();
    }

    if (xSemaphoreTake(ghota_lock, pdMS_TO_TICKS(1000)) != pdPASS) {
        ESP_LOGE(TAG, "Failed to take lock");
        return NULL;
    }

    ghota_client_handle_t *handle = malloc(sizeof(ghota_client_handle_t));
    if (handle == NULL) {
        ESP_LOGE(TAG, "Failed to allocate memory for client handle");
        xSemaphoreGive(ghota_lock);
        return NULL;
    }

    bzero(handle, sizeof(ghota_client_handle_t));
    strncpy(handle->config.fwFilenameMatch, newconfig->fwFilenameMatch, CONFIG_MAX_FILENAME_LEN);
    strncpy(handle->config.storageFilenameMatch, newconfig->storageFilenameMatch, CONFIG_MAX_FILENAME_LEN);
    strncpy(handle->config.storagePartitionName, newconfig->storagePartitionName, 17);

    if (newconfig->hostname == NULL)
        asprintf(&handle->config.hostname, CONFIG_GITHUB_HOSTNAME);
    else
        asprintf(&handle->config.hostname, newconfig->hostname);

    if (newconfig->orgname == NULL)
        asprintf(&handle->config.orgname, CONFIG_GITHUB_OWNER);
    else
        asprintf(&handle->config.orgname, newconfig->orgname);

    if (newconfig->reponame == NULL)
        asprintf(&handle->config.reponame, CONFIG_GITHUB_REPO);
    else
        asprintf(&handle->config.reponame, newconfig->reponame);

    const esp_app_desc_t *app_desc = esp_app_get_description();

    if (semver_parse(app_desc->version, &handle->currentversion)) {
        ESP_LOGE(TAG, "Failed to parse current version");
        ghota_free(handle);
        xSemaphoreGive(ghota_lock);
        return NULL;
    }

    handle->result.flags = 0;
    handle->config.updateInterval = newconfig->updateInterval;

    xSemaphoreGive(ghota_lock);

    return handle;
}

esp_err_t ghota_free(ghota_client_handle_t *handle) {
    if (xSemaphoreTake(ghota_lock, pdMS_TO_TICKS(1000)) != pdPASS) {
        ESP_LOGE(TAG, "Failed to take lock");
        return ESP_FAIL;
    }

    free(handle->config.hostname);
    free(handle->config.orgname);
    free(handle->config.reponame);

    if (handle->username)
        free(handle->username);

    if (handle->token)
        free(handle->token);

    semver_free(&handle->currentversion);
    semver_free(&handle->latestVersion);
    xSemaphoreGive(ghota_lock);

    return ESP_OK;
}

esp_err_t ghota_set_auth(ghota_client_handle_t *handle, const char *username, const char *password) {
    if (xSemaphoreTake(ghota_lock, pdMS_TO_TICKS(1000)) != pdPASS) {
        ESP_LOGE(TAG, "Failed to take lock");
        return ESP_FAIL;
    }

    asprintf(&handle->username, "%s", username);
    asprintf(&handle->token, "%s", password);
    xSemaphoreGive(ghota_lock);
    return ESP_OK;
}

static void lwjson_callback(lwjson_stream_parser_t *jsp, lwjson_stream_type_t type) {
    if (jsp->udata == NULL) {
        ESP_LOGE(TAG, "No user data for callback");
        return;
    }

    ghota_client_handle_t *handle = (ghota_client_handle_t *)jsp->udata;

    ESP_LOGD(TAG, "Lwjson Called: %d %d %d %d", jsp->stack_pos, jsp->stack[jsp->stack_pos - 1].type, type, handle->result.flags);

    if (jsp->stack[jsp->stack_pos - 1].type == LWJSON_STREAM_TYPE_KEY) {
        // We need key to be before
        ESP_LOGD(TAG, "Key: %s", jsp->stack[jsp->stack_pos - 1].meta.name);
    }

    // Get a value corresponsing to "tag_name" key
    if (!GetFlag(handle, GHOTA_RELEASE_GOT_TAG)) {
        if (jsp->stack_pos >= 2                                // Number of stack entries must be high
            && jsp->stack[0].type == LWJSON_STREAM_TYPE_OBJECT // First must be object
            && jsp->stack[1].type == LWJSON_STREAM_TYPE_KEY    // We need key to be before
            && strcmp(jsp->stack[1].meta.name, "tag_name") == 0) {
            ESP_LOGD(TAG, "Got key '%s' with value '%s'", jsp->stack[1].meta.name, jsp->data.str.buff);
            strncpy(handle->result.tagName, jsp->data.str.buff, CONFIG_MAX_FILENAME_LEN);
            SetFlag(handle, GHOTA_RELEASE_GOT_TAG);
        }
    }

    if (!GetFlag(handle, GHOTA_RELEASE_VALID_FIRMWARE) || !GetFlag(handle, GHOTA_RELEASE_VALID_STORAGE)) {
        if (jsp->stack_pos == 5
            && jsp->stack[0].type == LWJSON_STREAM_TYPE_OBJECT
            && jsp->stack[1].type == LWJSON_STREAM_TYPE_KEY
            && strcmp(jsp->stack[1].meta.name, "assets") == 0
            && jsp->stack[2].type == LWJSON_STREAM_TYPE_ARRAY
            && jsp->stack[3].type == LWJSON_STREAM_TYPE_OBJECT
            && jsp->stack[4].type == LWJSON_STREAM_TYPE_KEY) {

            ESP_LOGD(TAG, "Assets Got key '%s' with value '%s'", jsp->stack[jsp->stack_pos - 1].meta.name, jsp->data.str.buff);

            if (strcmp(jsp->stack[4].meta.name, "name") == 0) {
                SetFlag(handle, GHOTA_RELEASE_GOT_BINARY_NAME);
                strncpy(handle->scratch.name, jsp->data.str.buff, CONFIG_MAX_FILENAME_LEN);
                ESP_LOGD(TAG, "Got Filename for Asset: %s", handle->scratch.name);
            }

            if (strcmp(jsp->stack[4].meta.name, "url") == 0) {
                SetFlag(handle, GHOTA_RELEASE_GOT_BINARY_URL);
                strncpy(handle->scratch.url, jsp->data.str.buff, CONFIG_MAX_URL_LEN);
                ESP_LOGD(TAG, "Got URL for Asset: %s", handle->scratch.url);
            }

            // Now test if we got both name an download url
            if (GetFlag(handle, GHOTA_RELEASE_GOT_BINARY_NAME) && GetFlag(handle, GHOTA_RELEASE_GOT_BINARY_URL)) {
                ESP_LOGD(TAG, "Testing Firmware filenames %s -> %s - Matching Filename against %s and %s", handle->scratch.name, handle->scratch.url, handle->config.fwFilenameMatch, handle->config.storageFilenameMatch);

                // see if the filename matches
                if (!GetFlag(handle, GHOTA_RELEASE_VALID_FIRMWARE)
                    && fnmatch(handle->scratch.name, handle->config.fwFilenameMatch, 0) == 0) {
                    strncpy(handle->result.fwUrl, handle->scratch.url, CONFIG_MAX_URL_LEN);
                    ESP_LOGD(TAG, "Valid Firmware Found: %s - %s", handle->scratch.name, handle->result.fwUrl);
                    SetFlag(handle, GHOTA_RELEASE_VALID_FIRMWARE);
                } else if (!GetFlag(handle, GHOTA_RELEASE_VALID_STORAGE)
                            && fnmatch(handle->scratch.name, handle->config.storageFilenameMatch, 0) == 0) {
                    strncpy(handle->result.storageUrl, handle->scratch.url, CONFIG_MAX_URL_LEN);
                    ESP_LOGD(TAG, "Valid Storage Binary Found: %s - %s", handle->scratch.name, handle->result.storageUrl);
                    SetFlag(handle, GHOTA_RELEASE_VALID_STORAGE);
                }
            }
        }
    }
}

static esp_err_t _http_event_handler(esp_http_client_event_t *evt) {
    lwjsonr_t res;
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wswitch"
    switch (evt->event_id) {
        case HTTP_EVENT_ON_HEADER:
            if (strncasecmp(evt->header_key, "x-ratelimit-remaining", strlen("x-ratelimit-remaining")) == 0) {
                int limit = atoi(evt->header_value);

                ESP_LOGD(TAG, "Github API Rate Limit Remaining: %d", limit);

                if (limit < 10) {
                    ESP_LOGW(TAG, "Github API Rate Limit Remaining is low: %d", limit);
                }
            }
            break;
        case HTTP_EVENT_ON_DATA:
            if (!esp_http_client_is_chunked_response(evt->client)) {
                char *buf = evt->data;

                for (int i = 0; i < evt->data_len; i++) {
                    res = lwjson_stream_parse((lwjson_stream_parser_t *)evt->user_data, *buf);

                    if (!(res == lwjsonOK || res == lwjsonSTREAMDONE || res == lwjsonSTREAMINPROG)) {
                        ESP_LOGE(TAG, "Lwjson Error: %d", res);
                    }

                    buf++;
                }
            }
            break;
        case HTTP_EVENT_DISCONNECTED: {
            int mbedtls_err = 0;
            esp_err_t err = esp_tls_get_and_clear_last_error(evt->data, &mbedtls_err, NULL);

            if (err != 0) {
                ESP_LOGE(TAG, "Last esp error code: 0x%x", err);
                ESP_LOGE(TAG, "Last mbedtls failure: 0x%x", mbedtls_err);
            }
            break;
        }
    }
#pragma GCC diagnostic pop
    return ESP_OK;
}

esp_err_t ghota_check(ghota_client_handle_t *handle) {
    if (handle == NULL) {
        ESP_LOGE(TAG, "Invalid Handle");
        return ESP_ERR_INVALID_ARG;
    }

    if (xSemaphoreTake(ghota_lock, pdMS_TO_TICKS(1000)) != pdPASS) {
        ESP_LOGE(TAG, "Failed to get lock");
        return ESP_FAIL;
    }

    // clear all flags
    handle->result.flags = 0;

    ESP_ERROR_CHECK(esp_event_post(GHOTA_EVENTS, GHOTA_EVENT_START_CHECK, handle, sizeof(ghota_client_handle_t *), portMAX_DELAY));

    lwjson_stream_parser_t stream_parser;
    lwjsonr_t res;

    res = lwjson_stream_init(&stream_parser, lwjson_callback);

    if (res != lwjsonOK) {
        ESP_LOGE(TAG, "Failed to initialize JSON parser: %d", res);
        xSemaphoreGive(ghota_lock);
        return ESP_FAIL;
    }
    stream_parser.udata = (void *)handle;

    char url[CONFIG_MAX_URL_LEN];
    snprintf(url, CONFIG_MAX_URL_LEN, "https://%s/repos/%s/%s/releases/latest", handle->config.hostname, handle->config.orgname, handle->config.reponame);
    ESP_LOGD(TAG, "Searching for Firmware from %s", url);

    esp_http_client_config_t httpconfig = {
        .url = url,
        .crt_bundle_attach = esp_crt_bundle_attach,
        .event_handler = _http_event_handler,
        .user_data = &stream_parser,
    };

    if (handle->username) {
        ESP_LOGD(TAG, "Using Authenticated Request to %s", url);
        httpconfig.username = handle->username;
        httpconfig.password = handle->token;
        httpconfig.auth_type = HTTP_AUTH_TYPE_BASIC;
    }

    esp_http_client_handle_t client = esp_http_client_init(&httpconfig);
    esp_err_t err = esp_http_client_perform(client);

    if (err == ESP_OK) {
        ESP_LOGD(TAG, "HTTP GET Status = %d, content_length = %" PRId64,
                 esp_http_client_get_status_code(client),
                 esp_http_client_get_content_length(client));
    } else {
        ESP_LOGE(TAG, "HTTP GET request failed: %s", esp_err_to_name(err));
        esp_http_client_cleanup(client);
        xSemaphoreGive(ghota_lock);
        return ESP_FAIL;
    }

    if (esp_http_client_get_status_code(client) == 200) {
        if (GetFlag(handle, GHOTA_RELEASE_VALID_FIRMWARE)) {
            if (semver_parse(handle->result.tagName, &handle->latestVersion)) {
                ESP_LOGE(TAG, "Failed to parse new version");
                esp_http_client_cleanup(client);
                xSemaphoreGive(ghota_lock);
                return ESP_FAIL;
            }

            ESP_LOGI(TAG, "Current Version %d.%d.%d", handle->currentversion.major, handle->currentversion.minor, handle->currentversion.patch);
            ESP_LOGI(TAG, "New Version %d.%d.%d", handle->latestVersion.major, handle->latestVersion.minor, handle->latestVersion.patch);
            ESP_LOGI(TAG, "Firmware URL: %s", handle->result.fwUrl);

            if (GetFlag(handle, GHOTA_RELEASE_VALID_STORAGE)) {
                ESP_LOGI(TAG, "Storage URL: %s", handle->result.storageUrl);
            }
        } else {
            esp_http_client_cleanup(client);
            xSemaphoreGive(ghota_lock);
            return ESP_FAIL;
        }
    } else {
        ESP_LOGW(TAG, "Github Release API Returned: %d", esp_http_client_get_status_code(client));
        esp_http_client_cleanup(client);
        xSemaphoreGive(ghota_lock);
        return ESP_FAIL;
    }

    esp_http_client_cleanup(client);
    xSemaphoreGive(ghota_lock);
    return ESP_OK;
}

static esp_err_t validate_image_header(esp_app_desc_t *new_app_info) {
    if (new_app_info == NULL) {
        return ESP_ERR_INVALID_ARG;
    }

    ESP_LOGI(TAG, "New Firmware Details:");
    ESP_LOGI(TAG, "Project name: %s", new_app_info->project_name);
    ESP_LOGI(TAG, "Firmware version: %s", new_app_info->version);
    ESP_LOGI(TAG, "Compiled time: %s %s", new_app_info->date, new_app_info->time);
    ESP_LOGI(TAG, "ESP-IDF: %s", new_app_info->idf_ver);
    ESP_LOGI(TAG, "SHA256:");
    ESP_LOG_BUFFER_HEX(TAG, new_app_info->app_elf_sha256, sizeof(new_app_info->app_elf_sha256));

    const esp_partition_t *running = esp_ota_get_running_partition();

    ESP_LOGD(TAG, "Current partition %s type %d subtype %d (offset 0x%08" PRIx32 ")",
             running->label, running->type, running->subtype, running->address);

    const esp_partition_t *update = esp_ota_get_next_update_partition(NULL);

    ESP_LOGD(TAG, "Update partition %s type %d subtype %d (offset 0x%08" PRIx32 ")",
             update->label, update->type, update->subtype, update->address);

#ifdef CONFIG_BOOTLOADER_APP_ANTI_ROLLBACK
    /**
     * Secure version check from firmware image header prevents subsequent download and flash write of
     * entire firmware image. However this is optional because it is also taken care in API
     * esp_https_ota_finish at the end of OTA update procedure.
     */
    const uint32_t hw_sec_version = esp_efuse_read_secure_version();
    if (new_app_info->secure_version < hw_sec_version) {
        ESP_LOGW(TAG, "New firmware security version is less than eFuse programmed, %d < %d", new_app_info->secure_version, hw_sec_version);
        return ESP_FAIL;
    }
#endif

    return ESP_OK;
}

static esp_err_t http_client_set_header_cb(esp_http_client_handle_t http_client) {
    return esp_http_client_set_header(http_client, "Accept", "application/octet-stream");
}

esp_err_t _http_event_storage_handler(esp_http_client_event_t *evt) {
    static int output_pos;
    static int last_progress;
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wswitch"
    switch (evt->event_id) {
        case HTTP_EVENT_ON_CONNECTED: {
            output_pos = 0;
            last_progress = 0;
            /* Erase the Partition */
            break;
        }
        case HTTP_EVENT_ON_DATA:
            if (!esp_http_client_is_chunked_response(evt->client)) {
                ghota_client_handle_t *handle = (ghota_client_handle_t *)evt->user_data;
                if (output_pos == 0) {
                    ESP_LOGD(TAG, "Erasing partition");
                    ESP_ERROR_CHECK(esp_partition_erase_range(handle->storagePartition, 0, handle->storagePartition->size));
                    ESP_LOGD(TAG, "Erasing complete");
                }

                ESP_ERROR_CHECK(esp_partition_write(handle->storagePartition, output_pos, evt->data, evt->data_len));
                output_pos += evt->data_len;
                int progress = 100 * ((float)output_pos / (float)handle->storagePartition->size);

                if ((progress % 5 == 0) && (progress != last_progress)) {
                    ESP_LOGV(TAG, "Store binary update progress: %d%%", progress);
                    ESP_ERROR_CHECK(esp_event_post(GHOTA_EVENTS, GHOTA_EVENT_STORAGE_UPDATE_PROGRESS, &progress, sizeof(progress), portMAX_DELAY));
                    last_progress = progress;
                }
            }
            break;
        case HTTP_EVENT_DISCONNECTED: {
            int mbedtls_err = 0;
            esp_err_t err = esp_tls_get_and_clear_last_error(evt->data, &mbedtls_err, NULL);
            if (err != 0) {
                ESP_LOGE(TAG, "Last esp error code: 0x%x", err);
                ESP_LOGE(TAG, "Last mbedtls failure: 0x%x", mbedtls_err);
            }
            break;
        }
    }
#pragma GCC diagnostic pop
    return ESP_OK;
}

esp_err_t ghota_storage_update(ghota_client_handle_t *handle) {
    if (handle == NULL) {
        ESP_LOGE(TAG, "Invalid Handle");
        return ESP_ERR_INVALID_ARG;
    }

    if (!strlen(handle->result.storageUrl)) {
        ESP_LOGE(TAG, "No storage binary URL given");
        return ESP_ERR_INVALID_ARG;
    }

    if (!strlen(handle->config.storagePartitionName)) {
        ESP_LOGE(TAG, "No storage partition name given");
        return ESP_ERR_INVALID_ARG;
    }

    if (xSemaphoreTake(ghota_lock, pdMS_TO_TICKS(1000)) != pdTRUE) {
        ESP_LOGE(TAG, "Failed to take lock");
        return ESP_FAIL;
    }

    handle->storagePartition = esp_partition_find_first(ESP_PARTITION_TYPE_DATA, ESP_PARTITION_SUBTYPE_ANY, handle->config.storagePartitionName);
    if (handle->storagePartition == NULL) {
        ESP_LOGE(TAG, "Storage Partition Not Found");
        xSemaphoreGive(ghota_lock);
        return ESP_FAIL;
    }

    ESP_LOGD(TAG, "Storage Partition %s - Type %x Subtype %x Found at %" PRIx32 " - size %" PRId32, handle->storagePartition->label, handle->storagePartition->type, handle->storagePartition->subtype, handle->storagePartition->address, handle->storagePartition->size);
    ESP_ERROR_CHECK(esp_event_post(GHOTA_EVENTS, GHOTA_EVENT_START_STORAGE_UPDATE, NULL, 0, portMAX_DELAY));
    // give time for the system to react, such as unmounting the filesystems etc
    vTaskDelay(pdMS_TO_TICKS(1000));

    esp_http_client_config_t config = {
        .url = handle->result.storageUrl,
        .event_handler = _http_event_storage_handler,
        .crt_bundle_attach = esp_crt_bundle_attach,
        .user_data = handle,
        .buffer_size_tx = 2048,

    };

    if (handle->username) {
        ESP_LOGD(TAG, "Using Authenticated Request to %s", config.url);
        config.username = handle->username;
        config.password = handle->token;
        config.auth_type = HTTP_AUTH_TYPE_BASIC;
    }

    esp_http_client_handle_t client = esp_http_client_init(&config);
    ESP_ERROR_CHECK(esp_http_client_set_header(client, "Accept", "application/octet-stream"));
    esp_err_t err = esp_http_client_perform(client);

    if (err == ESP_OK) {
        ESP_LOGD(TAG, "HTTP GET Status = %d, content_length = %" PRId64,
                 esp_http_client_get_status_code(client),
                 esp_http_client_get_content_length(client));
        uint8_t sha256[32] = {0};
        ESP_ERROR_CHECK(esp_partition_get_sha256(handle->storagePartition, sha256));
        ESP_LOG_BUFFER_HEX("New storage partition SHA256:", sha256, sizeof(sha256));
        ESP_ERROR_CHECK(esp_event_post(GHOTA_EVENTS, GHOTA_EVENT_FINISH_STORAGE_UPDATE, NULL, 0, portMAX_DELAY));
    } else {
        ESP_LOGE(TAG, "HTTP GET request failed: %s", esp_err_to_name(err));
        ESP_ERROR_CHECK(esp_event_post(GHOTA_EVENTS, GHOTA_EVENT_STORAGE_UPDATE_FAILED, NULL, 0, portMAX_DELAY));
    }

    esp_http_client_cleanup(client);
    xSemaphoreGive(ghota_lock);
    return ESP_OK;
}

esp_err_t ghota_update(ghota_client_handle_t *handle) {
    esp_err_t ota_finish_err = ESP_OK;

    if (xSemaphoreTake(ghota_lock, pdMS_TO_TICKS(1000)) != pdTRUE) {
        ESP_LOGE(TAG, "Failed to take lock");
        return ESP_FAIL;
    }

    ESP_LOGI(TAG, "Starting firmware update");
    ESP_ERROR_CHECK(esp_event_post(GHOTA_EVENTS, GHOTA_EVENT_START_UPDATE, NULL, 0, portMAX_DELAY));

    if (!GetFlag(handle, GHOTA_RELEASE_VALID_FIRMWARE)) {
        ESP_LOGE(TAG, "No firmware binary found");
        ESP_ERROR_CHECK(esp_event_post(GHOTA_EVENTS, GHOTA_EVENT_UPDATE_FAILED, NULL, 0, portMAX_DELAY));
        xSemaphoreGive(ghota_lock);
        return ESP_FAIL;
    }

    if (semver_compare_version(handle->latestVersion, handle->currentversion) != 1) {
        ESP_LOGE(TAG, "Current version is equal or newer than new release");
        ESP_ERROR_CHECK(esp_event_post(GHOTA_EVENTS, GHOTA_EVENT_UPDATE_FAILED, NULL, 0, portMAX_DELAY));
        xSemaphoreGive(ghota_lock);
        return ESP_OK;
    }

    esp_http_client_config_t httpconfig = {
        .url = handle->result.fwUrl,
        .crt_bundle_attach = esp_crt_bundle_attach,
        .keep_alive_enable = true,
        .buffer_size_tx = 4096,
    };

    if (handle->username) {
        ESP_LOGD(TAG, "Using Authenticated Request to %s", httpconfig.url);
        httpconfig.username = handle->username;
        httpconfig.password = handle->token;
        httpconfig.auth_type = HTTP_AUTH_TYPE_BASIC;
    }

    esp_https_ota_config_t ota_config = {
        .http_config = &httpconfig,
        .http_client_init_cb = http_client_set_header_cb,
    };

    esp_https_ota_handle_t https_ota_handle = NULL;
    esp_err_t err = esp_https_ota_begin(&ota_config, &https_ota_handle);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "ESP HTTPS OTA Begin failed: %d", err);
        goto ota_end;
    }

    esp_app_desc_t app_desc;
    err = esp_https_ota_get_img_desc(https_ota_handle, &app_desc);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "esp_https_ota_read_img_desc failed: %d", err);
        goto ota_end;
    }

    err = validate_image_header(&app_desc);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "image header verification failed: %d", err);
        goto ota_end;
    }
    int last_progress = -1;

    while (1) {
        err = esp_https_ota_perform(https_ota_handle);

        if (err != ESP_ERR_HTTPS_OTA_IN_PROGRESS) {
            break;
        }

        int32_t dl = esp_https_ota_get_image_len_read(https_ota_handle);
        int32_t size = esp_https_ota_get_image_size(https_ota_handle);

        int progress = 100 * ((float)dl / (float)size);

        if ((progress % 5 == 0) && (progress != last_progress)) {
            ESP_ERROR_CHECK(esp_event_post(GHOTA_EVENTS, GHOTA_EVENT_FIRMWARE_UPDATE_PROGRESS, &progress, sizeof(progress), portMAX_DELAY));
            ESP_LOGV(TAG, "Firmware Update Progress: %d%%", progress);
            last_progress = progress;
        }
    }

    if (esp_https_ota_is_complete_data_received(https_ota_handle) != true) {
        ESP_LOGE(TAG, "Data truncation. Failed to download the firmware binary.");
    } else {
        ota_finish_err = esp_https_ota_finish(https_ota_handle);

        if ((err == ESP_OK) && (ota_finish_err == ESP_OK)) {
            ESP_ERROR_CHECK(esp_event_post(GHOTA_EVENTS, GHOTA_EVENT_FINISH_UPDATE, NULL, 0, portMAX_DELAY));

            if (strlen(handle->result.storageUrl)) {
                xSemaphoreGive(ghota_lock);

                if (ghota_storage_update(handle) == ESP_OK) {
                    ESP_LOGI(TAG, "Storage update successful");
                } else {
                    ESP_LOGE(TAG, "Storage update failed");
                }
            } else {
                xSemaphoreGive(ghota_lock);
            }

            ESP_LOGI(TAG, "ESP_HTTPS_OTA upgrade successful. Rebooting ...");
            ESP_ERROR_CHECK(esp_event_post(GHOTA_EVENTS, GHOTA_EVENT_PENDING_REBOOT, NULL, 0, portMAX_DELAY));
            vTaskDelay(1000 / portTICK_PERIOD_MS);
            esp_restart();

            return ESP_OK;
        } else {
            if (ota_finish_err == ESP_ERR_OTA_VALIDATE_FAILED) {
                ESP_LOGE(TAG, "Image validation failed, image is corrupted");
            }

            ESP_LOGE(TAG, "ESP_HTTPS_OTA upgrade failed 0x%x", ota_finish_err);
            ESP_ERROR_CHECK(esp_event_post(GHOTA_EVENTS, GHOTA_EVENT_UPDATE_FAILED, NULL, 0, portMAX_DELAY));
            xSemaphoreGive(ghota_lock);

            return ESP_FAIL;
        }
    }

ota_end:
    esp_https_ota_abort(https_ota_handle);
    ESP_LOGE(TAG, "ESP_HTTPS_OTA upgrade failed");
    ESP_ERROR_CHECK(esp_event_post(GHOTA_EVENTS, GHOTA_EVENT_UPDATE_FAILED, NULL, 0, portMAX_DELAY));
    xSemaphoreGive(ghota_lock);
    return ESP_FAIL;
}

semver_t *ghota_get_current_version(ghota_client_handle_t *handle) {
    if (!handle) {
        return NULL;
    }

    semver_t *cur = malloc(sizeof(semver_t));
    memcpy(cur, &handle->currentversion, sizeof(semver_t));
    return cur;
}

semver_t *ghota_get_latest_version(ghota_client_handle_t *handle) {
    if (!handle) {
        return NULL;
    }

    if (!GetFlag(handle, GHOTA_RELEASE_VALID_FIRMWARE)) {
        return NULL;
    }

    semver_t *new = malloc(sizeof(semver_t));
    memcpy(new, &handle->latestVersion, sizeof(semver_t));
    return new;
}

static void ghota_task(void *pvParameters) {
    ghota_client_handle_t *handle = (ghota_client_handle_t *)pvParameters;

    if (ghota_check(handle) == ESP_OK) {
        if (semver_compare_version(handle->latestVersion, handle->currentversion) == 1) {
            ESP_LOGI(TAG, "A new version is available");
            ESP_ERROR_CHECK(esp_event_post(GHOTA_EVENTS, GHOTA_EVENT_UPDATE_AVAILABLE, handle, sizeof(ghota_client_handle_t *), portMAX_DELAY));

            ghota_update(handle);
        } else {
            ESP_LOGI(TAG, "No new version available");
            ESP_ERROR_CHECK(esp_event_post(GHOTA_EVENTS, GHOTA_EVENT_NO_UPDATE_AVAILABLE, NULL, 0, portMAX_DELAY));
        }
    } else {
        ESP_ERROR_CHECK(esp_event_post(GHOTA_EVENTS, GHOTA_EVENT_CHECK_ERROR, NULL, 0, portMAX_DELAY));
    }

    vTaskDelete(NULL);
}

esp_err_t ghota_start_update_task(ghota_client_handle_t *handle) {
    if (!handle) {
        return ESP_FAIL;
    }

    eTaskState state = eInvalid;
    TaskHandle_t tmp = xTaskGetHandle("ghota_task");

    if (tmp) {
        state = eTaskGetState(tmp);
    }

    if (state == eDeleted || state == eInvalid) {
        ESP_LOGD(TAG, "Starting Task to Check for Updates");

        if (xTaskCreate(ghota_task, "ghota_task", 6144, handle, 5, NULL) != pdPASS) {
            ESP_LOGE(TAG, "Failed to Start ghota_task");
            return ESP_FAIL;
        }
    } else {
        ESP_LOGW(TAG, "ghota_task Already Running");
        return ESP_FAIL;
    }

    return ESP_OK;
}

static void ghota_timer_callback(TimerHandle_t xTimer) {
    ghota_client_handle_t *handle = (ghota_client_handle_t *)pvTimerGetTimerID(xTimer);

    if (handle) {
        if (handle->countdown <= 0) {
            handle->countdown = handle->config.updateInterval;
            ghota_start_update_task(handle);
        }

        handle->countdown--;
    }
}

esp_err_t ghota_start_update_timer(ghota_client_handle_t *handle) {
    if (!handle) {
        ESP_LOGE(TAG, "Failed to initialize GHOTA Client");
        return ESP_FAIL;
    }

    handle->countdown = 0;

    /* run timer every minute */
    uint64_t ticks = pdMS_TO_TICKS(1000) * 60;
    TimerHandle_t timer = xTimerCreate("ghota_timer", ticks, pdTRUE, (void *)handle, ghota_timer_callback);

    if (timer == NULL) {
        ESP_LOGE(TAG, "Failed to create timer");
        return ESP_FAIL;
    } else {
        if (xTimerStart(timer, 0) != pdPASS) {
            ESP_LOGE(TAG, "Failed to start timer");
            return ESP_FAIL;
        } else {
            ESP_LOGI(TAG, "Started Update Timer for %" PRIu32 " Minutes", handle->config.updateInterval);
        }
    }

    return ESP_OK;
}

char* ghota_get_event_str(ghota_event_e event) {
    switch (event) {
        case GHOTA_EVENT_START_CHECK:
            return "GHOTA_EVENT_START_CHECK";
        case GHOTA_EVENT_CHECK_ERROR:
            return "GHOTA_EVENT_CHECK_ERROR";
        case GHOTA_EVENT_UPDATE_AVAILABLE:
            return "GHOTA_EVENT_UPDATE_AVAILABLE";
        case GHOTA_EVENT_NO_UPDATE_AVAILABLE:
            return "GHOTA_EVENT_NO_UPDATE_AVAILABLE";
        case GHOTA_EVENT_START_UPDATE:
            return "GHOTA_EVENT_START_UPDATE";
        case GHOTA_EVENT_FINISH_UPDATE:
            return "GHOTA_EVENT_FINISH_UPDATE";
        case GHOTA_EVENT_UPDATE_FAILED:
            return "GHOTA_EVENT_UPDATE_FAILED";
        case GHOTA_EVENT_START_STORAGE_UPDATE:
            return "GHOTA_EVENT_START_STORAGE_UPDATE";
        case GHOTA_EVENT_FINISH_STORAGE_UPDATE:
            return "GHOTA_EVENT_FINISH_STORAGE_UPDATE";
        case GHOTA_EVENT_STORAGE_UPDATE_FAILED:
            return "GHOTA_EVENT_STORAGE_UPDATE_FAILED";
        case GHOTA_EVENT_FIRMWARE_UPDATE_PROGRESS:
            return "GHOTA_EVENT_FIRMWARE_UPDATE_PROGRESS";
        case GHOTA_EVENT_STORAGE_UPDATE_PROGRESS:
            return "GHOTA_EVENT_STORAGE_UPDATE_PROGRESS";
        case GHOTA_EVENT_PENDING_REBOOT:
            return "GHOTA_EVENT_PENDING_REBOOT";
    }
    return "Unknown Event";
}