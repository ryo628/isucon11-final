package model

// CourseResultのうち計算しなくていいやつ
type SimpleCourseResult struct {
	Name        string // course name
	Code        string // course code
	ClassScores []*SimpleClassScore
}

func NewSimpleCourseResult(name, code string, classScores []*SimpleClassScore) *SimpleCourseResult {
	return &SimpleCourseResult{
		Name:        name,
		Code:        code,
		ClassScores: classScores,
	}

}

type SimpleClassScore struct {
	// 上3つの情報はclassから取得できるので無くてもいいかもしれない
	ClassID string
	Title   string
	Part    uint8

	Score int // 0 - 100点
}

func NewSimpleClassScore(class *Class, score int) *SimpleClassScore {
	return &SimpleClassScore{
		ClassID: class.ID,
		Title:   class.Title,
		Part:    class.Part,
		Score:   score,
	}
}

type GradeRes struct {
	Summary       Summary
	CourseResults map[string]*CourseResult
}

func NewGradeRes(summary Summary, courseResults map[string]*CourseResult) GradeRes {
	return GradeRes{
		Summary:       summary,
		CourseResults: courseResults,
	}
}

type Summary struct {
	Credits   int
	GPT       float64
	GptTScore float64 // 偏差値
	GptAvg    float64 // 平均値
	GptMax    float64 // 最大値
	GptMin    float64 // 最小値
}

type CourseResult struct {
	Name             string
	Code             string
	TotalScore       int
	TotalScoreTScore float64 // 偏差値
	TotalScoreAvg    float64 // 平均値
	TotalScoreMax    int     // 最大値
	TotalScoreMin    int     // 最小値
	ClassScores      []*ClassScore
}

func NewCourseResult(Name, Code string, TotalScore, TotalScoreMax, TotalScoreMin int, TotalScoreTScore, TotalScoreAvg float64, ClassScores []*ClassScore) *CourseResult {
	return &CourseResult{
		Name,
		Code,
		TotalScore,
		TotalScoreTScore,
		TotalScoreAvg,
		TotalScoreMax,
		TotalScoreMin,
		ClassScores,
	}
}

type ClassScore struct {
	// 上3つの情報はclassから取得できるので無くてもいいかもしれない
	ClassID string
	Title   string
	Part    uint8

	Score          int // 0 - 100点
	SubmitterCount int
}

func NewClassScore(class *Class, score, submitterCount int) *ClassScore {
	return &ClassScore{
		ClassID:        class.ID,
		Title:          class.Title,
		Part:           class.Part,
		Score:          score,
		SubmitterCount: submitterCount,
	}
}
