#
# Copyright 2014-2015 eNovance
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.
from collections import defaultdict
import fnmatch
import itertools
import json
import operator
import os
import threading

from gnocchiclient import exceptions as gnocchi_exc
from keystoneauth1 import exceptions as ka_exceptions
from oslo_log import log
from oslo_utils import timeutils
from stevedore import extension
import tenacity
from urllib import parse as urlparse

from ceilometer import cache_utils
from ceilometer import declarative
from ceilometer import gnocchi_client
from ceilometer.i18n import _
from ceilometer import keystone_client
from ceilometer import publisher

LOG = log.getLogger(__name__)


EVENT_CREATE, EVENT_UPDATE, EVENT_DELETE = ("create", "update", "delete")


class ResourcesDefinition(object):

    MANDATORY_FIELDS = {'resource_type': str,
                        'metrics': (dict, list)}

    MANDATORY_EVENT_FIELDS = {'id': str}

    def __init__(self, definition_cfg, archive_policy_default,
                 archive_policy_override, plugin_manager):
        self.cfg = definition_cfg

        self._check_required_and_types(self.MANDATORY_FIELDS, self.cfg)

        if self.support_events():
            self._check_required_and_types(self.MANDATORY_EVENT_FIELDS,
                                           self.cfg['event_attributes'])

        self._attributes = {}
        for name, attr_cfg in self.cfg.get('attributes', {}).items():
            self._attributes[name] = declarative.Definition(name, attr_cfg,
                                                            plugin_manager)

        self._event_attributes = {}
        for name, attr_cfg in self.cfg.get('event_attributes', {}).items():
            self._event_attributes[name] = declarative.Definition(
                name, attr_cfg, plugin_manager)

        self.metrics = {}

        # NOTE(sileht): Convert old list to new dict format
        if isinstance(self.cfg['metrics'], list):
            values = [None] * len(self.cfg['metrics'])
            self.cfg['metrics'] = dict(zip(self.cfg['metrics'], values))

        for m, extra in self.cfg['metrics'].items():
            if not extra:
                extra = {}

            if not extra.get("archive_policy_name"):
                extra["archive_policy_name"] = archive_policy_default

            if archive_policy_override:
                extra["archive_policy_name"] = archive_policy_override

            # NOTE(sileht): For backward compat, this is after the override to
            # preserve the wierd previous behavior. We don't really care as we
            # deprecate it.
            if 'archive_policy' in self.cfg:
                LOG.warning("archive_policy '%s' for a resource-type (%s) is "
                            "deprecated, set it for each metric instead.",
                            self.cfg["archive_policy"],
                            self.cfg["resource_type"])
                extra["archive_policy_name"] = self.cfg['archive_policy']

            self.metrics[m] = extra

    @staticmethod
    def _check_required_and_types(expected, definition):
        for field, field_types in expected.items():
            if field not in definition:
                raise declarative.ResourceDefinitionException(
                    _("Required field %s not specified") % field, definition)
            if not isinstance(definition[field], field_types):
                raise declarative.ResourceDefinitionException(
                    _("Required field %(field)s should be a %(type)s") %
                    {'field': field, 'type': field_types}, definition)

    @staticmethod
    def _ensure_list(value):
        if isinstance(value, list):
            return value
        return [value]

    def support_events(self):
        for e in ["event_create", "event_delete", "event_update"]:
            if e in self.cfg:
                return True
        return False

    def event_match(self, event_type):
        for e in self._ensure_list(self.cfg.get('event_create', [])):
            if fnmatch.fnmatch(event_type, e):
                return EVENT_CREATE
        for e in self._ensure_list(self.cfg.get('event_delete', [])):
            if fnmatch.fnmatch(event_type, e):
                return EVENT_DELETE
        for e in self._ensure_list(self.cfg.get('event_update', [])):
            if fnmatch.fnmatch(event_type, e):
                return EVENT_UPDATE

    def sample_attributes(self, sample):
        attrs = {}
        sample_dict = sample.as_dict()
        for name, definition in self._attributes.items():
            value = definition.parse(sample_dict)
            if value is not None:
                attrs[name] = value
        return attrs

    def event_attributes(self, event):
        attrs = {'type': self.cfg['resource_type']}
        traits = dict([(trait.name, trait.value) for trait in event.traits])
        for attr, field in self.cfg.get('event_attributes', {}).items():
            value = traits.get(field)
            if value is not None:
                attrs[attr] = value
        return attrs


class LockedDefaultDict(defaultdict):
    """defaultdict with lock to handle threading

    Dictionary only deletes if nothing is accessing dict and nothing is holding
    lock to be deleted. If both cases are not true, it will skip delete.
    """
    def __init__(self, *args, **kwargs):
        self.lock = threading.Lock()
        super(LockedDefaultDict, self).__init__(*args, **kwargs)

    def __getitem__(self, key):
        with self.lock:
            return super(LockedDefaultDict, self).__getitem__(key)

    def pop(self, key, *args):
        with self.lock:
            key_lock = super(LockedDefaultDict, self).__getitem__(key)
            if key_lock.acquire(False):
                try:
                    super(LockedDefaultDict, self).pop(key, *args)
                finally:
                    key_lock.release()


class GnocchiPublisher(publisher.ConfigPublisherBase):
    """Publisher class for recording metering data into the Gnocchi service.

    The publisher class records each meter into the gnocchi service
    configured in Ceilometer pipeline file. An example target may
    look like the following:

      gnocchi://?archive_policy=low&filter_project=gnocchi
    """
    def __init__(self, conf, parsed_url):
        super(GnocchiPublisher, self).__init__(conf, parsed_url)
        # TODO(jd) allow to override Gnocchi endpoint via the host in the URL
        options = urlparse.parse_qs(parsed_url.query)

        self.filter_project = options.get('filter_project', ['service'])[-1]
        self.filter_domain = options.get('filter_domain', ['Default'])[-1]

        resources_definition_file = options.get(
            'resources_definition_file', ['gnocchi_resources.yaml'])[-1]

        archive_policy_override = options.get('archive_policy', [None])[-1]
        self.resources_definition, self.archive_policies_definition = (
            self._load_definitions(conf, archive_policy_override,
                                   resources_definition_file))
        self.metric_map = dict((metric, rd) for rd in self.resources_definition
                               for metric in rd.metrics)

        timeout = options.get('timeout', [6.05])[-1]
        self._ks_client = keystone_client.get_client(conf)

        # NOTE(cdent): The default cache backend is a real but
        # noop backend. We don't want to use that here because
        # we want to avoid the cache pathways entirely if the
        # cache has not been configured explicitly.
        self.cache = cache_utils.get_client(conf)

        self._gnocchi_project_id = None
        self._gnocchi_project_id_lock = threading.Lock()
        self._gnocchi_resource_lock = LockedDefaultDict(threading.Lock)

        try:
            self._gnocchi = self._get_gnocchi_client(conf, timeout)
        except tenacity.RetryError as e:
            raise e.last_attempt._exception from None

        self._already_logged_event_types = set()
        self._already_logged_metric_names = set()

        self._already_configured_archive_policies = False

    @tenacity.retry(
        stop=tenacity.stop_after_attempt(10),
        wait=tenacity.wait_fixed(5),
        retry=(
            tenacity.retry_if_exception_type(ka_exceptions.ServiceUnavailable)
            | tenacity.retry_if_exception_type(ka_exceptions.DiscoveryFailure)
            | tenacity.retry_if_exception_type(ka_exceptions.ConnectTimeout)
        ),
        reraise=False)
    def _get_gnocchi_client(self, conf, timeout):
        return gnocchi_client.get_gnocchiclient(conf, request_timeout=timeout)

    @staticmethod
    def _load_definitions(conf, archive_policy_override,
                          resources_definition_file):
        plugin_manager = extension.ExtensionManager(
            namespace='ceilometer.event.trait_plugin')
        data = declarative.load_definitions(
            conf, {}, resources_definition_file,
            os.path.join(os.path.dirname(os.path.abspath(__file__)),
                         'data', 'gnocchi_resources.yaml'))

        archive_policy_default = data.get("archive_policy_default",
                                          "ceilometer-low")
        resource_defs = []
        for resource in data.get('resources', []):
            try:
                resource_defs.append(ResourcesDefinition(
                    resource,
                    archive_policy_default,
                    archive_policy_override,
                    plugin_manager))
            except Exception:
                LOG.error("Failed to load resource due to error",
                          exc_info=True)
        return resource_defs, data.get("archive_policies", [])

    def ensures_archives_policies(self):
        if not self._already_configured_archive_policies:
            for ap in self.archive_policies_definition:
                try:
                    self._gnocchi.archive_policy.create(ap)
                except gnocchi_exc.ArchivePolicyAlreadyExists:
                    # created in the meantime by another worker
                    pass
            self._already_configured_archive_policies = True

    @property
    def gnocchi_project_id(self):
        if self._gnocchi_project_id is not None:
            return self._gnocchi_project_id
        with self._gnocchi_project_id_lock:
            if self._gnocchi_project_id is None:
                if not self.filter_project:
                    LOG.debug(
                        "Multiple executions were locked on "
                        "self._gnocchi_project_id_lock`. This execution "
                        "should no call `_internal_gnocchi_project_discovery` "
                        "as `self.filter_project` is None.")
                    return None
                try:
                    domain = self._ks_client.domains.find(
                        name=self.filter_domain)
                    project = self._ks_client.projects.find(
                        name=self.filter_project,
                        domain_id=domain.id)
                except ka_exceptions.NotFound:
                    LOG.warning('Filtered project [%s] not found in keystone, '
                                'ignoring the filter_project option' %
                                self.filter_project)

                    self.filter_project = None
                    return None
                except Exception:
                    LOG.exception('Failed to retrieve filtered project [%s].'
                                  % self.filter_project)
                    raise
                self._gnocchi_project_id = project.id
                LOG.debug("Filtered project [%s] found with ID [%s].",
                          self.filter_project, self._gnocchi_project_id)
            return self._gnocchi_project_id

    def _is_swift_account_sample(self, sample):
        try:
            return (self.metric_map[sample.name].cfg['resource_type']
                    == 'swift_account')
        except KeyError:
            return False

    def _is_gnocchi_activity(self, sample):
        return (self.filter_project and self.gnocchi_project_id and (
            # avoid anything from the user used by gnocchi
            sample.project_id == self.gnocchi_project_id or
            # avoid anything in the swift account used by gnocchi
            (sample.resource_id == self.gnocchi_project_id and
             self._is_swift_account_sample(sample))
        ))

    def _get_resource_definition_from_event(self, event_type):
        for rd in self.resources_definition:
            operation = rd.event_match(event_type)
            if operation:
                return rd, operation

    def filter_gnocchi_activity_openstack(self, samples):
        """Skip sample generated by gnocchi itself

        This method will filter out the samples that are generated by
        Gnocchi itself.
        """
        filtered_samples = []
        for sample in samples:
            if not self._is_gnocchi_activity(sample):
                filtered_samples.append(sample)
                LOG.debug("Sample [%s] is not a Gnocchi activity; therefore, "
                          "we do not filter it out and push it to Gnocchi.",
                          sample)
            else:
                LOG.debug("Sample [%s] is a Gnocchi activity; therefore, "
                          "we filter it out and do not push it to Gnocchi.",
                          sample)
        return filtered_samples

    # Skip-on-ended state for deleted resources.
    #
    # Gnocchi clears a resource's ``ended_at`` whenever it ingests a
    # measure that matches certain timestamp/bucket conditions, which
    # resurrects deleted resources when audit jobs (e.g. Cinder's
    # ``volume_usage_audit``) replay notifications. Rather than publish
    # measures that might resurrect a resource, we skip them: the
    # authoritative "final measurement at deletion" has already been
    # captured by the matching delete-event notification, so late
    # samples are redundant.
    _ENDED_AT_CACHE_PREFIX = 'gnocchi_publisher:ended_at:'
    _ENDED_AT_SENTINEL_ALIVE = ''

    def _get_cached_ended_state(self, resource_id):
        """Return cached state for ``resource_id``.

        ``True`` means Gnocchi has an ``ended_at`` on this resource,
        ``False`` means it has been confirmed alive, and ``None`` means
        no cached state (caller may consult Gnocchi as a fallback).
        """
        if not self.cache or not resource_id:
            return None
        cached = self.cache.get(self._ENDED_AT_CACHE_PREFIX + resource_id)
        if cached is None or not isinstance(cached, str):
            return None
        return cached != self._ENDED_AT_SENTINEL_ALIVE

    @staticmethod
    def _sample_indicates_deleted(sample):
        """Return True when a sample advertises a deleted resource.

        Triggers the authoritative Gnocchi fallback. Any ``status`` whose
        lowercase form contains ``delet`` is treated as a signal; this
        catches ``deleted``, ``deleting``, ``error_deleting`` and the
        like across Cinder, Nova, Glance, Manila, etc. Samples without a
        ``status`` (some notification paths filter it out) simply don't
        trigger the fallback; those flows are covered by the cache
        warmed in :meth:`_set_ended_at`.
        """
        metadata = sample.resource_metadata or {}
        status = metadata.get('status')
        return isinstance(status, str) and 'delet' in status.lower()

    def _lookup_ended_state_from_gnocchi(self, resource_type, resource_id):
        """Ask Gnocchi whether a resource is ended, and cache the answer.

        Called at most once per resource per batch, only when the cache
        is cold and a sample signals deletion. Returns ``True`` when the
        resource has ``ended_at`` set, ``False`` when it is alive or
        unknown to Gnocchi, and ``None`` on failure (fail-open: caller
        will publish the sample).
        """
        try:
            resource = self._gnocchi.resource.get(resource_type, resource_id)
        except gnocchi_exc.ResourceNotFound:
            # Will be created by the upcoming batch call; treat as alive.
            if self.cache:
                self.cache.set(
                    self._ENDED_AT_CACHE_PREFIX + resource_id,
                    self._ENDED_AT_SENTINEL_ALIVE)
            return False
        except Exception:
            LOG.debug(
                "Gnocchi ended_at lookup failed for [%s]/[%s]; "
                "publishing samples unchanged.",
                resource_type, resource_id, exc_info=True)
            return None

        # ``resource`` is a plain dict from gnocchiclient in production,
        # but unit tests may return a bare Mock(). Require a real string
        # before treating the value as a valid ended_at.
        raw = resource.get('ended_at') if isinstance(resource, dict) else None
        cache_value = raw if isinstance(raw, str) and raw else (
            self._ENDED_AT_SENTINEL_ALIVE)
        if self.cache:
            self.cache.set(
                self._ENDED_AT_CACHE_PREFIX + resource_id, cache_value)
        return cache_value != self._ENDED_AT_SENTINEL_ALIVE

    def publish_samples(self, data):
        self.ensures_archives_policies()

        data = self.filter_gnocchi_activity_openstack(data)

        def value_to_sort(object_to_sort):
            value = object_to_sort.resource_id
            if not value:
                LOG.debug("Resource ID was not defined for sample data [%s]. "
                          "Therefore, we will use an empty string as the "
                          "resource ID.", object_to_sort)
                value = ''

            return value

        data.sort(key=value_to_sort)
        resource_grouped_samples = itertools.groupby(
            data, key=operator.attrgetter('resource_id'))

        gnocchi_data = {}
        measures = {}
        for resource_id, samples_of_resource in resource_grouped_samples:
            # Resolve deletion state at most once per batch. Materialize
            # the group so we can both probe it for a deletion signal and
            # iterate a second time to publish.
            samples_of_resource = list(samples_of_resource)
            resource_ended = self._get_cached_ended_state(resource_id)
            if resource_ended is None and resource_id and any(
                    self._sample_indicates_deleted(s)
                    for s in samples_of_resource):
                resource_type_hint = next(
                    (self.metric_map[s.name].cfg['resource_type']
                     for s in samples_of_resource
                     if s.name in self.metric_map),
                    None)
                if resource_type_hint is not None:
                    resource_ended = self._lookup_ended_state_from_gnocchi(
                        resource_type_hint, resource_id)

            for sample in samples_of_resource:
                metric_name = sample.name
                LOG.debug("Processing sample [%s] for resource ID [%s].",
                          sample, resource_id)

                if resource_ended:
                    # Publishing would risk resurrecting the resource in
                    # Gnocchi. The final measurement at deletion is
                    # already captured by the delete-event notification.
                    LOG.debug(
                        "Skipping sample [%s] for deleted resource [%s].",
                        sample, resource_id)
                    continue

                rd = self.metric_map.get(metric_name)
                if rd is None:
                    if metric_name not in self._already_logged_metric_names:
                        LOG.warning("metric %s is not handled by Gnocchi" %
                                    metric_name)
                        self._already_logged_metric_names.add(metric_name)
                    continue

                # NOTE(sileht): / is forbidden by Gnocchi
                resource_id = resource_id.replace('/', '_')

                if resource_id not in gnocchi_data:
                    gnocchi_data[resource_id] = {
                        'resource_type': rd.cfg['resource_type'],
                        'resource': {"id": resource_id,
                                     "user_id": sample.user_id,
                                     "project_id": sample.project_id}}

                gnocchi_data[resource_id].setdefault(
                    "resource_extra", {}).update(rd.sample_attributes(sample))
                measures.setdefault(resource_id, {}).setdefault(
                    metric_name,
                    {"measures": [],
                     "archive_policy_name":
                     rd.metrics[metric_name]["archive_policy_name"],
                     "unit": sample.unit}
                )["measures"].append(
                    {'timestamp': sample.timestamp,
                     'value': sample.volume}
                )

        try:
            self.batch_measures(measures, gnocchi_data)
        except gnocchi_exc.ClientException as e:
            LOG.error("Gnocchi client exception while pushing measures [%s] "
                      "for gnocchi data [%s]: [%s].", measures, gnocchi_data,
                      str(e))
        except Exception as e:
            LOG.error("Unexpected exception while pushing measures [%s] for "
                      "gnocchi data [%s]: [%s].", measures, gnocchi_data,
                      str(e), exc_info=True)

        for info in gnocchi_data.values():
            resource = info["resource"]
            resource_type = info["resource_type"]
            resource_extra = info["resource_extra"]
            if not resource_extra:
                continue
            try:
                self._if_not_cached(resource_type, resource['id'],
                                    resource_extra)
            except gnocchi_exc.ClientException as e:
                LOG.error("Gnocchi client exception updating resource type "
                          "[%s] with ID [%s] for resource data [%s]: [%s].",
                          resource_type, resource.get('id'), resource_extra,
                          str(e))
            except Exception as e:
                LOG.error("Unexpected exception updating resource type [%s] "
                          "with ID [%s] for resource data [%s]: [%s].",
                          resource_type, resource.get('id'), resource_extra,
                          str(e), exc_info=True)

    @staticmethod
    def _extract_resources_from_error(e, resource_infos):
        resource_ids = set([r['original_resource_id']
                            for r in e.message['detail']])
        return [(resource_infos[rid]['resource_type'],
                 resource_infos[rid]['resource'],
                 resource_infos[rid]['resource_extra'])
                for rid in resource_ids]

    def batch_measures(self, measures, resource_infos):
        # NOTE(sileht): We don't care about error here, we want
        # resources metadata always been updated
        try:
            LOG.debug("Executing batch resource metrics measures for resource "
                      "[%s] and measures [%s].", resource_infos, measures)

            self._gnocchi.metric.batch_resources_metrics_measures(
                measures, create_metrics=True)
        except gnocchi_exc.BadRequest as e:
            if not isinstance(e.message, dict):
                raise
            if e.message.get('cause') != 'Unknown resources':
                raise

            resources = self._extract_resources_from_error(e, resource_infos)
            for resource_type, resource, resource_extra in resources:
                try:
                    resource.update(resource_extra)
                    self._create_resource(resource_type, resource)
                except gnocchi_exc.ResourceAlreadyExists:
                    # NOTE(sileht): resource created in the meantime
                    pass
                except gnocchi_exc.ClientException as e:
                    LOG.error('Error creating resource %(id)s: %(err)s',
                              {'id': resource['id'], 'err': str(e)})
                    # We cannot post measures for this resource
                    # and we can't patch it later
                    del measures[resource['id']]
                    del resource_infos[resource['id']]
                else:
                    if self.cache and resource_extra:
                        self.cache.set(resource['id'],
                                       self._hash_resource(resource_extra))

            # NOTE(sileht): we have created missing resources/metrics,
            # now retry to post measures
            self._gnocchi.metric.batch_resources_metrics_measures(
                measures, create_metrics=True)

        LOG.debug(
            "%d measures posted against %d metrics through %d resources",
            sum(len(m["measures"])
                for rid in measures
                for m in measures[rid].values()),
            sum(len(m) for m in measures.values()), len(resource_infos))

    def _create_resource(self, resource_type, resource):
        self._gnocchi.resource.create(resource_type, resource)
        LOG.debug('Resource %s created', resource["id"])

    def _update_resource(self, resource_type, res_id, resource_extra):
        self._gnocchi.resource.update(resource_type, res_id, resource_extra)
        LOG.debug('Resource %s updated', res_id)

    def _if_not_cached(self, resource_type, res_id, resource_extra):
        if self.cache:
            attribute_hash = self._hash_resource(resource_extra)
            if self._resource_cache_diff(res_id, attribute_hash):
                with self._gnocchi_resource_lock[res_id]:
                    # NOTE(luogangyi): there is a possibility that the
                    # resource was already built in cache by another
                    # ceilometer-notification-agent when we get the lock here.
                    if self._resource_cache_diff(res_id, attribute_hash):
                        self._update_resource(resource_type, res_id,
                                              resource_extra)
                        self.cache.set(res_id, attribute_hash)
                    else:
                        LOG.debug('Resource cache hit for %s', res_id)
                self._gnocchi_resource_lock.pop(res_id, None)
            else:
                LOG.debug('Resource cache hit for %s', res_id)
        else:
            self._update_resource(resource_type, res_id, resource_extra)

    @staticmethod
    def _hash_resource(resource):
        return hash(tuple(i for i in resource.items() if i[0] != 'metrics'))

    def _resource_cache_diff(self, key, attribute_hash):
        cached_hash = self.cache.get(key)
        return not cached_hash or cached_hash != attribute_hash

    def publish_events(self, events):
        for event in events:
            rd = self._get_resource_definition_from_event(event.event_type)
            if not rd:
                if event.event_type not in self._already_logged_event_types:
                    LOG.debug("No gnocchi definition for event type: %s",
                              event.event_type)
                    self._already_logged_event_types.add(event.event_type)
                continue

            rd, operation = rd
            if operation == EVENT_DELETE:
                self._delete_event(rd, event)
            if operation == EVENT_CREATE:
                self._create_event(rd, event)
            if operation == EVENT_UPDATE:
                self._update_event(rd, event)

    def _update_event(self, rd, event):
        resource = rd.event_attributes(event)
        associated_resources = rd.cfg.get('event_associated_resources', {})

        if associated_resources:
            to_update = itertools.chain([resource], *[
                self._search_resource(resource_type, query % resource['id'])
                for resource_type, query in associated_resources.items()
            ])
        else:
            to_update = [resource]

        for resource in to_update:
            self._set_update_attributes(resource)

    def _delete_event(self, rd, event):
        ended_at = timeutils.utcnow().isoformat()

        resource = rd.event_attributes(event)
        associated_resources = rd.cfg.get('event_associated_resources', {})

        if associated_resources:
            to_end = itertools.chain([resource], *[
                self._search_resource(resource_type, query % resource['id'])
                for resource_type, query in associated_resources.items()
            ])
        else:
            to_end = [resource]

        for resource in to_end:
            self._set_ended_at(resource, ended_at)

    def _create_event(self, rd, event):
        resource = rd.event_attributes(event)
        resource_type = resource.pop('type')

        try:
            self._create_resource(resource_type, resource)
        except gnocchi_exc.ResourceAlreadyExists:
            LOG.debug("Create event received on existing resource (%s), "
                      "ignore it.", resource['id'])
        except Exception:
            LOG.error("Failed to create resource %s", resource,
                      exc_info=True)

    def _search_resource(self, resource_type, query):
        try:
            return self._gnocchi.resource.search(
                resource_type, json.loads(query))
        except Exception:
            LOG.error("Fail to search resource type %(resource_type)s "
                      "with '%(query)s'",
                      {'resource_type': resource_type, 'query': query},
                      exc_info=True)
        return []

    def _set_update_attributes(self, resource):
        resource_id = resource.pop('id')
        resource_type = resource.pop('type')

        try:
            self._if_not_cached(resource_type, resource_id, resource)
        except gnocchi_exc.ResourceNotFound:
            LOG.debug("Update event received on unexisting resource (%s), "
                      "ignore it.", resource_id)
        except Exception:
            LOG.error("Fail to update the resource %s", resource,
                      exc_info=True)

    def _set_ended_at(self, resource, ended_at):
        try:
            self._gnocchi.resource.update(resource['type'], resource['id'],
                                          {'ended_at': ended_at})
        except gnocchi_exc.ResourceNotFound:
            LOG.debug("Delete event received on unexisting resource (%s), "
                      "ignore it.", resource['id'])
        except Exception:
            LOG.error("Fail to update the resource %s", resource,
                      exc_info=True)
        else:
            # Warm the ended_at cache so subsequent publish_samples
            # calls skip measures for this resource without a round-trip.
            if self.cache:
                self.cache.set(
                    self._ENDED_AT_CACHE_PREFIX + resource['id'], ended_at)
        LOG.debug('Resource %(resource_id)s ended at %(ended_at)s',
                  {'resource_id': resource["id"], 'ended_at': ended_at})
