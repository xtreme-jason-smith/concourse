module Dashboard.Filter exposing (filterGroups)

import Concourse
import Concourse.PipelineStatus
    exposing
        ( PipelineStatus(..)
        , StatusDetails(..)
        , equal
        , isRunning
        )
import Dashboard.Group.Models exposing (Group, Pipeline)
import Dashboard.Pipeline as Pipeline
import Dict exposing (Dict)
import Parser
    exposing
        ( (|.)
        , (|=)
        , Parser
        , Step(..)
        , backtrackable
        , chompWhile
        , end
        , getChompedString
        , keyword
        , loop
        , map
        , oneOf
        , run
        , spaces
        , succeed
        , symbol
        )
import Simple.Fuzzy


type alias Filter =
    { negate : Bool
    , groupFilter : GroupFilter
    }


filterGroups : Dict ( String, String ) (List Concourse.Job) -> String -> List Concourse.Team -> List Pipeline -> List Group
filterGroups existingJobs query teams pipelines =
    let
        groupsToFilter =
            pipelines
                |> List.foldr
                    (\p ->
                        Dict.update p.teamName
                            (Maybe.withDefault []
                                >> (::) p
                                >> Just
                            )
                    )
                    (teams
                        |> List.map (\team -> ( team.name, [] ))
                        |> Dict.fromList
                    )
                |> Dict.toList
                |> List.map (\( k, v ) -> { teamName = k, pipelines = v })
    in
    parseFilters query |> List.foldr (runFilter existingJobs) groupsToFilter


runFilter : Dict ( String, String ) (List Concourse.Job) -> Filter -> List Group -> List Group
runFilter existingJobs f =
    let
        negater =
            if f.negate then
                not

            else
                identity
    in
    case f.groupFilter of
        Team teamName ->
            List.filter (.teamName >> Simple.Fuzzy.match teamName >> negater)

        Pipeline pf ->
            List.map
                (\g ->
                    { g
                        | pipelines =
                            g.pipelines
                                |> List.filter (pipelineFilter pf existingJobs >> negater)
                    }
                )
                >> List.filter (.pipelines >> List.isEmpty >> not)


pipelineFilter : PipelineFilter -> Dict ( String, String ) (List Concourse.Job) -> Pipeline -> Bool
pipelineFilter pf existingJobs pipeline =
    let
        jobsForPipeline =
            existingJobs
                |> Dict.get ( pipeline.teamName, pipeline.name )
                |> Maybe.withDefault []
    in
    case pf of
        Status sf ->
            case sf of
                PipelineStatus ps ->
                    pipeline |> Pipeline.pipelineStatus jobsForPipeline |> equal ps

                PipelineRunning ->
                    pipeline |> Pipeline.pipelineStatus jobsForPipeline |> isRunning

        FuzzyName term ->
            pipeline.name |> Simple.Fuzzy.match term


parseFilters : String -> List Filter
parseFilters =
    run
        (loop [] <|
            \revFilters ->
                oneOf
                    [ end
                        |> map (\_ -> Done (List.reverse revFilters))
                    , filter
                        |> map (\f -> Loop (f :: revFilters))
                    ]
        )
        >> Result.withDefault []


filter : Parser Filter
filter =
    oneOf
        [ succeed (Filter True) |. spaces |. symbol "-" |= groupFilter |. spaces
        , succeed (Filter False) |. spaces |= groupFilter |. spaces
        ]


type GroupFilter
    = Team String
    | Pipeline PipelineFilter


type PipelineFilter
    = Status StatusFilter
    | FuzzyName String


groupFilter : Parser GroupFilter
groupFilter =
    oneOf
        [ backtrackable teamFilter
        , backtrackable statusFilter
        , succeed (FuzzyName >> Pipeline) |= parseWord
        ]


parseWord : Parser String
parseWord =
    getChompedString
        (chompWhile
            (\c -> c /= ' ' && c /= '\t' && c /= '\n' && c /= '\u{000D}')
        )


type StatusFilter
    = PipelineStatus PipelineStatus
    | PipelineRunning


teamFilter : Parser GroupFilter
teamFilter =
    succeed Team
        |. keyword "team"
        |. symbol ":"
        |. spaces
        |= parseWord


statusFilter : Parser GroupFilter
statusFilter =
    succeed (Status >> Pipeline)
        |. keyword "status"
        |. symbol ":"
        |. spaces
        |= pipelineStatus


pipelineStatus : Parser StatusFilter
pipelineStatus =
    oneOf
        [ map (\_ -> PipelineStatus PipelineStatusPaused) (keyword "paused")
        , map (\_ -> PipelineStatus <| PipelineStatusAborted Running)
            (keyword "aborted")
        , map (\_ -> PipelineStatus <| PipelineStatusErrored Running)
            (keyword "errored")
        , map (\_ -> PipelineStatus <| PipelineStatusFailed Running)
            (keyword "failed")
        , map (\_ -> PipelineStatus <| PipelineStatusPending False)
            (keyword "pending")
        , map (\_ -> PipelineStatus <| PipelineStatusSucceeded Running)
            (keyword "succeeded")
        , map (\_ -> PipelineRunning) (keyword "running")
        ]
