package db_test

import (
	"code.cloudfoundry.org/lager"
	"code.cloudfoundry.org/lager/lagertest"
	"errors"
	"time"

	"github.com/concourse/concourse/atc"
	"github.com/concourse/concourse/atc/db"
	"github.com/concourse/concourse/atc/db/dbfakes"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("CheckFactory", func() {

	var (
		err                 error
		resourceConfigScope db.ResourceConfigScope
		metadata            db.CheckMetadata
	)

	BeforeEach(func() {
		setupTx, err := dbConn.Begin()
		Expect(err).ToNot(HaveOccurred())

		brt := db.BaseResourceType{
			Name: "some-base-resource-type",
		}

		_, err = brt.FindOrCreate(setupTx, false)
		Expect(err).NotTo(HaveOccurred())
		Expect(setupTx.Commit()).To(Succeed())

		resourceConfigScope, err = defaultResource.SetResourceConfig(atc.Source{"some": "repository"}, atc.VersionedResourceTypes{})
		Expect(err).NotTo(HaveOccurred())

		metadata = db.CheckMetadata{
			TeamID:             defaultTeam.ID(),
			TeamName:           defaultTeam.Name(),
			PipelineName:       defaultPipeline.Name(),
			ResourceConfigID:   resourceConfigScope.ResourceConfig().ID(),
			BaseResourceTypeID: resourceConfigScope.ResourceConfig().OriginBaseResourceType().ID,
		}
	})

	Describe("Check", func() {
		var created, found bool
		var check, foundCheck db.Check

		BeforeEach(func() {
			check, created, err = checkFactory.CreateCheck(
				resourceConfigScope.ID(),
				false,
				atc.Plan{Check: &atc.CheckPlan{Name: "some-name", Type: "some-type"}},
				metadata,
			)
			Expect(created).To(BeTrue())
			Expect(err).NotTo(HaveOccurred())
		})

		JustBeforeEach(func() {
			foundCheck, found, err = checkFactory.Check(check.ID())
		})

		It("succeeds", func() {
			Expect(found).To(BeTrue())
			Expect(err).NotTo(HaveOccurred())
		})

		It("returns the db check", func() {
			Expect(foundCheck).To(Equal(check))
		})
	})

	Describe("TryCreateCheck", func() {

		var (
			created bool
			check   db.Check

			fakeResource      *dbfakes.FakeResource
			fakeResourceType  *dbfakes.FakeResourceType
			fakeResourceTypes []db.ResourceType
			fromVersion       atc.Version
			manuallyTriggered bool
			logger            lager.Logger
		)

		BeforeEach(func() {
			fromVersion = atc.Version{"from": "version"}

			fakeResource = new(dbfakes.FakeResource)
			fakeResource.NameReturns("some-name")
			fakeResource.TagsReturns([]string{"tag-a", "tag-b"})
			fakeResource.SourceReturns(atc.Source{"some": "source"})
			fakeResource.PipelineIDReturns(defaultPipeline.ID())
			fakeResource.PipelineNameReturns(defaultPipeline.Name())
			fakeResource.PipelineReturns(defaultPipeline, true, nil)

			fakeResourceType = new(dbfakes.FakeResourceType)
			fakeResourceType.NameReturns("some-type")
			fakeResourceType.TypeReturns("some-base-type")
			fakeResourceType.TagsReturns([]string{"some-tag"})
			fakeResourceType.SourceReturns(atc.Source{"some": "type-source"})
			fakeResourceType.PipelineIDReturns(defaultPipeline.ID())
			fakeResourceType.PipelineNameReturns(defaultPipeline.Name())
			fakeResourceType.PipelineReturns(defaultPipeline, true, nil)

			fakeResourceTypes = []db.ResourceType{fakeResourceType}
			manuallyTriggered = true

			logger = lagertest.NewTestLogger("db-test")
		})

		JustBeforeEach(func() {
			check, created, err = checkFactory.TryCreateCheck(logger, fakeResource, fakeResourceTypes, fromVersion, manuallyTriggered)
		})

		Context("when the resource parent type is not a custom type", func() {
			BeforeEach(func() {
				fakeResource.TypeReturns("base-type")
			})

			Context("when the configured timeout is not parseable", func() {
				BeforeEach(func() {
					fakeResource.CheckTimeoutReturns("not-a-duration")
				})

				It("errors", func() {
					Expect(err).To(HaveOccurred())
				})
			})

			Context("when the configured timeout is parseable", func() {
				BeforeEach(func() {
					fakeResource.CheckTimeoutReturns("10s")
				})

				Context("when evaluating the source fails", func() {
					BeforeEach(func() {
						fakeResource.SourceReturns(atc.Source{"some": "((secret))"})
						fakeSecrets.GetReturns("", nil, false, nil)
					})

					It("errors", func() {
						Expect(err).To(HaveOccurred())
					})
				})

				Context("when evaluating the source succeeds", func() {
					BeforeEach(func() {
						fakeResource.SourceReturns(atc.Source{"some": "((secret))"})
						fakeSecrets.GetReturns("source", nil, true, nil)
					})

					Context("when evaluating the resource types source fails", func() {
						BeforeEach(func() {
							fakeResourceType.SourceReturns(atc.Source{"some": "((other-secret))"})
							fakeSecrets.GetReturns("", nil, false, nil)
						})

						It("errors", func() {
							Expect(err).To(HaveOccurred())
						})
					})

					Context("when evaluating the resource types source succeeds", func() {
						BeforeEach(func() {
							fakeResourceType.SourceReturns(atc.Source{"some": "((other-secret))"})
							fakeSecrets.GetReturns("source", nil, true, nil)
						})

						Context("when updating the resource config scope fails", func() {
							BeforeEach(func() {
								fakeResource.SetResourceConfigReturns(nil, errors.New("nope"))
							})

							It("errors", func() {
								Expect(err).To(HaveOccurred())
							})
						})

						Context("when updating the resource config scope succeeds", func() {
							BeforeEach(func() {
								fakeResource.SetResourceConfigReturns(resourceConfigScope, nil)
							})

							Context("when fromVersion is not nil", func() {
								BeforeEach(func() {
									fromVersion = atc.Version{"version": "a"}
								})

								It("creates a check", func() {
									Expect(err).NotTo(HaveOccurred())
									Expect(created).To(BeTrue())
									Expect(check).NotTo(BeNil())
								})

								It("creates a plan with a version", func() {
									Expect(check.Plan().Check.FromVersion).To(Equal(atc.Version{"version": "a"}))
									Expect(check.Plan().Check.Name).To(Equal("some-name"))
									Expect(check.Plan().Check.Type).To(Equal("base-type"))
									Expect(check.Plan().Check.Source).To(Equal(atc.Source{"some": "((secret))"}))
									Expect(check.Plan().Check.Tags).To(ConsistOf("tag-a", "tag-b"))
									Expect(check.Plan().Check.Timeout).To(Equal("10s"))
								})
							})

							Context("when fromVersion is nil", func() {
								BeforeEach(func() {
									fromVersion = nil
								})

								Context("when fetching the latest version returns not found", func() {
									BeforeEach(func() {
										_, err = dbConn.Exec("DELETE FROM resource_config_versions")
										Expect(err).NotTo(HaveOccurred())
									})

									It("creates a check", func() {
										Expect(err).NotTo(HaveOccurred())
										Expect(created).To(BeTrue())
										Expect(check).NotTo(BeNil())
									})

									It("creates a plan with a nil version", func() {
										Expect(check.Plan().Check.FromVersion).To(BeNil())
										Expect(check.Plan().Check.Name).To(Equal("some-name"))
										Expect(check.Plan().Check.Type).To(Equal("base-type"))
										Expect(check.Plan().Check.Source).To(Equal(atc.Source{"some": "((secret))"}))
										Expect(check.Plan().Check.Tags).To(ConsistOf("tag-a", "tag-b"))
										Expect(check.Plan().Check.Timeout).To(Equal("10s"))
									})
								})

								Context("when fetching the latest version returns a version", func() {

									BeforeEach(func() {
										err = resourceConfigScope.SaveVersions([]atc.Version{{"some": "version"}})
										Expect(err).NotTo(HaveOccurred())
									})

									It("creates a check", func() {
										Expect(err).NotTo(HaveOccurred())
										Expect(created).To(BeTrue())
										Expect(check).NotTo(BeNil())
									})

									It("creates a plan with a version", func() {
										Expect(check.Plan().Check.FromVersion).To(Equal(atc.Version{"some": "version"}))
										Expect(check.Plan().Check.Name).To(Equal("some-name"))
										Expect(check.Plan().Check.Type).To(Equal("base-type"))
										Expect(check.Plan().Check.Source).To(Equal(atc.Source{"some": "((secret))"}))
										Expect(check.Plan().Check.Tags).To(ConsistOf("tag-a", "tag-b"))
										Expect(check.Plan().Check.Timeout).To(Equal("10s"))
									})
								})
							})
						})
					})
				})
			})
		})

		Context("when the resource has a parent type", func() {
			BeforeEach(func() {
				fakeResource.TypeReturns("custom-type")
				fakeResource.PipelineIDReturns(1)
				fakeResourceType.NameReturns("custom-type")
				fakeResourceType.PipelineIDReturns(1)

			})

			Context("when the resource and type are properly configured", func() {
				BeforeEach(func() {
					fakeResourceType.LastCheckEndTimeReturns(time.Now().Add(-time.Hour))
					fakeResource.LastCheckEndTimeReturns(time.Now().Add(-time.Hour))

					fakeResource.SetResourceConfigReturns(resourceConfigScope, nil)
				})

				Context("when the parent type has no version", func() {
					BeforeEach(func() {
						fakeResourceType.VersionReturns(nil)
					})

					It("errors", func() {
						Expect(err).To(HaveOccurred())
					})
				})

				Context("when the parent type has a version", func() {
					BeforeEach(func() {
						fakeResourceType.VersionReturns(atc.Version{"some": "version"})
					})

					It("creates a check", func() {
						Expect(err).NotTo(HaveOccurred())
						Expect(created).To(BeTrue())
						Expect(check).NotTo(BeNil())
					})

					It("creates a plan for the resource", func() {
						Expect(check.Plan().Check.FromVersion).To(Equal(atc.Version{"from": "version"}))
						Expect(check.Plan().Check.Name).To(Equal("some-name"))
						Expect(check.Plan().Check.Type).To(Equal("custom-type"))
						Expect(check.Plan().Check.Source).To(Equal(atc.Source{"some": "source"}))
						Expect(check.Plan().Check.Tags).To(ConsistOf("tag-a", "tag-b"))
						Expect(check.Plan().Check.Timeout).To(Equal("1m0s"))
					})
				})
			})
		})
	})

	Describe("CreateCheck", func() {
		var created bool
		var check db.Check

		JustBeforeEach(func() {
			check, created, err = checkFactory.CreateCheck(
				resourceConfigScope.ID(),
				false,
				atc.Plan{Check: &atc.CheckPlan{Name: "some-name", Type: "some-type"}},
				metadata,
			)
		})

		It("succeeds", func() {
			Expect(created).To(BeTrue())
			Expect(err).NotTo(HaveOccurred())
		})

		It("returns the resource check", func() {
			Expect(check.ID()).To(Equal(1))
			Expect(check.TeamID()).To(Equal(defaultTeam.ID()))
			Expect(check.Status()).To(Equal(db.CheckStatusStarted))
			Expect(check.Schema()).To(Equal("exec.v2"))
			Expect(check.Plan().Check.Name).To(Equal("some-name"))
			Expect(check.Plan().Check.Type).To(Equal("some-type"))
			Expect(check.CreateTime()).To(BeTemporally("~", time.Now(), time.Second))
			Expect(check.ResourceConfigScopeID()).To(Equal(resourceConfigScope.ID()))
			Expect(check.ResourceConfigID()).To(Equal(resourceConfigScope.ResourceConfig().ID()))
			Expect(check.BaseResourceTypeID()).To(Equal(resourceConfigScope.ResourceConfig().OriginBaseResourceType().ID))
		})

		Context("when a check is already pending", func() {
			BeforeEach(func() {
				_, created, err := checkFactory.CreateCheck(
					resourceConfigScope.ID(),
					false,
					atc.Plan{},
					metadata,
				)
				Expect(created).To(BeTrue())
				Expect(err).NotTo(HaveOccurred())
			})

			It("doesn't create a check", func() {
				Expect(created).To(BeFalse())
				Expect(err).NotTo(HaveOccurred())
			})
		})
	})

	Describe("StartedChecks", func() {
		var (
			checks []db.Check
		)

		JustBeforeEach(func() {
			checks, err = checkFactory.StartedChecks()
			Expect(err).NotTo(HaveOccurred())
		})

		Context("when looking up the resource check returns no results", func() {
			BeforeEach(func() {
				_, err = dbConn.Exec(`DELETE FROM checks`)
				Expect(err).NotTo(HaveOccurred())
			})

			It("is not found", func() {
				Expect(checks).To(HaveLen(0))
			})
		})

		Context("when a check has no metadata", func() {
			BeforeEach(func() {
				_, err = dbConn.Exec(`INSERT INTO checks(resource_config_scope_id, status, schema) VALUES ($1, 'started', 'some-schema')`, resourceConfigScope.ID())
				Expect(err).NotTo(HaveOccurred())
			})

			It("returns the check", func() {
				Expect(checks).To(HaveLen(1))
				Expect(checks[0].ID()).To(Equal(1))
				Expect(checks[0].Status()).To(Equal(db.CheckStatusStarted))
				Expect(checks[0].Schema()).To(Equal("some-schema"))
				Expect(checks[0].TeamID()).To(Equal(0))
				Expect(checks[0].ResourceConfigScopeID()).To(Equal(resourceConfigScope.ID()))
				Expect(checks[0].ResourceConfigID()).To(Equal(0))
				Expect(checks[0].BaseResourceTypeID()).To(Equal(0))
			})
		})

		Context("when looking up the resource check succeeds", func() {
			var check db.Check

			BeforeEach(func() {
				var created bool
				check, created, err = checkFactory.CreateCheck(
					resourceConfigScope.ID(),
					false,
					atc.Plan{},
					metadata,
				)
				Expect(created).To(BeTrue())
				Expect(err).NotTo(HaveOccurred())
			})

			It("returns the resource checks", func() {
				Expect(checks).To(HaveLen(1))
				Expect(checks[0]).To(Equal(check))
			})
		})
	})

	Describe("Resources", func() {
		var (
			resources []db.Resource
		)

		JustBeforeEach(func() {
			resources, err = checkFactory.Resources()
			Expect(err).NotTo(HaveOccurred())
		})

		// The default job doesn't use any resource, thus check should not run
		// against un-used resource.
		It("no resources in return", func() {
			Expect(resources).To(HaveLen(0))
		})

		Context("when the resources are used", func() {

			BeforeEach(func(){
				defaultPipeline, _, err = defaultTeam.SavePipeline("default-pipeline", atc.Config{
					Jobs: atc.JobConfigs{
						{
							Name: "some-job",
							Plan: atc.PlanSequence{
								atc.PlanConfig{Get: "some-resource"},
								atc.PlanConfig{Put: "some-resource-put-only"},
							},
						},
					},
					Resources: atc.ResourceConfigs{
						{
							Name: "some-resource",
							Type: "some-base-resource-type",
							Source: atc.Source{
								"some": "source",
							},
						},
						{
							Name: "some-resource-put-only",
							Type: "some-base-resource-type",
							Source: atc.Source{
								"some": "source",
							},
						},
					},
					ResourceTypes: atc.ResourceTypes{
						{
							Name: "some-type",
							Type: "some-base-resource-type",
							Source: atc.Source{
								"some-type": "source",
							},
						},
					},
				}, db.ConfigVersion(1), false)
				Expect(err).NotTo(HaveOccurred())

				_, found, err := defaultPipeline.Resource("some-resource")
				Expect(err).NotTo(HaveOccurred())
				Expect(found).To(BeTrue())

				_, found, err = defaultPipeline.Resource("some-resource-put-only")
				Expect(err).NotTo(HaveOccurred())
				Expect(found).To(BeTrue())
			})

			It("include only get-resources in return", func() {
				Expect(resources).To(HaveLen(1))
				Expect(resources[0].Name()).To(Equal("some-resource"))
			})

			Context("when the resource is not active", func() {
				BeforeEach(func() {
					_, err = dbConn.Exec(`UPDATE resources SET active = false`)
					Expect(err).NotTo(HaveOccurred())
				})

				It("does not return the resource", func() {
					Expect(resources).To(HaveLen(0))
				})
			})

			Context("when the resource pipeline is paused", func() {
				BeforeEach(func() {
					_, err = dbConn.Exec(`UPDATE pipelines SET paused = true`)
					Expect(err).NotTo(HaveOccurred())
				})

				It("does not return the resource", func() {
					Expect(resources).To(HaveLen(0))
				})
			})
		})
	})

	Describe("ResourceTypes", func() {
		var (
			resourceTypes db.ResourceTypes
		)

		JustBeforeEach(func() {
			resourceTypes, err = checkFactory.ResourceTypes()
			Expect(err).NotTo(HaveOccurred())
		})

		It("include resource types in return", func() {
			Expect(resourceTypes).To(HaveLen(1))
			Expect(resourceTypes[0].Name()).To(Equal("some-type"))
		})

		Context("when the resource type is not active", func() {
			BeforeEach(func() {
				_, err = dbConn.Exec(`UPDATE resource_types SET active = false`)
				Expect(err).NotTo(HaveOccurred())
			})

			It("does not return the resource type", func() {
				Expect(resourceTypes).To(HaveLen(0))
			})
		})
	})
})
