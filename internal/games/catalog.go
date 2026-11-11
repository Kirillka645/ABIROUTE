package games

import "abiroute/internal/config"

type GameProfile struct {
	ID            string   `json:"id"`
	Name          string   `json:"name"`
	ShortCode     string   `json:"shortCode"`
	Category      string   `json:"category"`
	RegionHint    string   `json:"regionHint"`
	Description   string   `json:"description"`
	Featured      bool     `json:"featured"`
	Custom        bool     `json:"custom"`
	Processes     []string `json:"processes"`
	PresetRanges  []string `json:"presetRanges"`
	WideRanges    []string `json:"wideRanges"`
	IgnoreRanges  []string `json:"ignoreRanges"`
	VerifyTargets []string `json:"verifyTargets"`
}

var BuiltinGames = []GameProfile{
	{
		ID:          "abi",
		Name:        "Arena Breakout: Infinite",
		ShortCode:   "ABI",
		Category:    "Тактический экстракшен-шутер",
		RegionHint:  "Европа · Азия · Америка",
		Description: "Точечный split-tunnel только для серверов лобби и рейдов. Discord, браузер и загрузка патчей идут напрямую на полной скорости провайдера.",
		Featured:    true,
		Processes:   []string{"UAGame.exe", "ArenaBreakoutInfinite.exe", "ArenaBreakoutInfiniteLauncher.exe"},
		PresetRanges: []string{
			"35.228.24.0/24", "43.128.81.0/24", "43.128.85.0/24", "43.128.88.0/24",
			"43.128.102.0/24", "43.131.60.0/24", "43.134.108.0/24", "43.134.152.0/24",
			"43.134.153.0/24", "43.153.253.0/24", "43.156.147.0/24", "43.157.67.0/24",
			"43.163.53.0/24", "43.163.63.0/24", "43.168.141.0/24", "43.174.218.0/24",
			"43.174.250.0/24", "43.174.251.0/24", "101.32.107.0/24", "101.32.110.0/24",
			"101.32.113.0/24", "101.32.143.0/24", "101.32.171.0/24", "101.33.43.0/24",
			"101.33.48.0/24", "119.28.109.0/24", "119.28.123.0/24", "129.226.1.0/24",
			"129.226.2.0/24", "129.226.155.0/24", "150.109.0.0/24", "150.109.27.0/24",
			"150.109.28.0/24", "161.120.165.0/24", "162.62.221.0/24", "184.24.77.0/24",
			"188.43.72.0/24",
		},
		WideRanges: []string{
			"43.153.0.0/16", "43.163.0.0/16", "43.168.0.0/16", "43.174.0.0/16",
			"101.32.0.0/16", "101.33.0.0/16", "129.226.0.0/16", "188.43.72.0/24",
		},
		IgnoreRanges:  []string{"92.122.0.0/15"},
		VerifyTargets: []string{"43.174.251.100", "43.134.152.44", "101.33.48.30"},
	},
	{
		ID:          "delta-force",
		Name:        "Delta Force",
		ShortCode:   "DF",
		Category:    "Тактический шутер",
		RegionHint:  "Европа · Франкфурт / Стокгольм",
		Description: "Оптимизация маршрута к серверам Level Infinite и автоматический захват UDP-серверов матчей через ETW-радар.",
		Processes:   []string{"DeltaForceClient-Win64-Shipping.exe", "DeltaForce.exe"},
		PresetRanges: []string{
			"43.153.253.0/24", "43.163.53.0/24", "43.174.218.0/24", "43.174.250.0/24",
			"101.32.107.0/24", "129.226.1.0/24", "150.109.27.0/24",
		},
		IgnoreRanges:  []string{"92.122.0.0/15"},
		VerifyTargets: []string{"43.174.250.10", "43.163.53.10"},
	},
	{
		ID:          "eft",
		Name:        "Escape from Tarkov",
		ShortCode:   "EFT",
		Category:    "Хардкорный экстракшен",
		RegionHint:  "Европа · Хельсинки / Франкфурт",
		Description: "Снижение потерь пакетов и обход проблемных магистралей провайдера при входе в рейд.",
		Processes:   []string{"EscapeFromTarkov.exe", "EscapeFromTarkov_BE.exe"},
		PresetRanges: []string{
			"92.223.80.0/24", "92.223.100.0/24", "185.136.168.0/24", "5.188.140.0/24",
		},
		IgnoreRanges:  []string{},
		VerifyTargets: []string{"92.223.80.1", "1.1.1.1"},
	},
	{
		ID:          "pubg",
		Name:        "PUBG: Battlegrounds",
		ShortCode:   "PUBG",
		Category:    "Королевская битва",
		RegionHint:  "Европа · AWS Франкфурт",
		Description: "Прямой туннель до европейских кластеров AWS с защитой от скачков джиттера и потери пакетов.",
		Processes:   []string{"TslGame.exe"},
		PresetRanges: []string{
			"3.64.0.0/16", "18.156.0.0/16", "52.28.0.0/16",
		},
		IgnoreRanges:  []string{},
		VerifyTargets: []string{"3.64.1.1", "18.156.1.1"},
	},
	{
		ID:          "cs2",
		Name:        "Counter-Strike 2",
		ShortCode:   "CS2",
		Category:    "Киберспортивный шутер",
		RegionHint:  "Стокгольм · Вена · Франкфурт",
		Description: "ETW-радар автоматически направляет реле Valve SDR через быстрый узел без влияния на Steam-загрузки.",
		Processes:   []string{"cs2.exe"},
		PresetRanges: []string{
			"155.133.248.0/24", "155.133.252.0/24", "162.254.196.0/24", "162.254.197.0/24",
		},
		IgnoreRanges:  []string{},
		VerifyTargets: []string{"155.133.248.34", "162.254.197.36"},
	},
	{
		ID:          "apex",
		Name:        "Apex Legends",
		ShortCode:   "APEX",
		Category:    "Королевская битва",
		RegionHint:  "Франкфурт · Амстердам",
		Description: "Исправление пакет-лосса на некоторых европейских инстансах EA/Multiplay (маршрутизация на лету).",
		Processes:   []string{"r5apex.exe", "r5apex_dx12.exe"},
		PresetRanges: []string{
			"52.58.0.0/16", "35.156.0.0/16", "18.194.0.0/16",
		},
		IgnoreRanges:  []string{},
		VerifyTargets: []string{"52.58.81.34", "1.1.1.1"},
	},
}

func AllGames(custom []config.CustomGame) []GameProfile {
	out := make([]GameProfile, 0, len(BuiltinGames)+len(custom))
	out = append(out, BuiltinGames...)
	for _, cg := range custom {
		short := cg.ShortCode
		if short == "" && len(cg.Name) >= 2 {
			short = cg.Name[:2]
		}
		cat := cg.Category
		if cat == "" {
			cat = "Пользовательское приложение"
		}
		out = append(out, GameProfile{
			ID:           cg.ID,
			Name:         cg.Name,
			ShortCode:    short,
			Category:     cat,
			RegionHint:   "Авто-захват ETW",
			Description:  "Маршрутизация только обнаруженных подключений выбранного процесса.",
			Custom:       true,
			Processes:    cg.Processes,
			PresetRanges: cg.PresetRanges,
			IgnoreRanges: cg.IgnoreRanges,
		})
	}
	return out
}

func FindGame(id string, custom []config.CustomGame) GameProfile {
	all := AllGames(custom)
	for _, g := range all {
		if g.ID == id {
			return g
		}
	}
	return BuiltinGames[0]
}
